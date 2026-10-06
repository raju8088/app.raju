import hmac
import json
import mimetypes
import re
import sys
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler
from typing import Any

from omnidim_ui import config
from omnidim_ui.config import (
    MAX_REQUEST_BODY_BYTES,
    STATIC_DIR,
    STATIC_SECURITY_HEADERS,
)
from omnidim_ui.db import (
    clear_history,
    compact_json,
    get_db,
    get_history,
    log_history,
    now_iso,
    read_settings,
    save_setting,
)
from omnidim_ui.endpoints import ENDPOINTS, GROUPS, match_endpoint
from omnidim_ui.logging_config import logger
from omnidim_ui.proxy import build_url, execute_proxy_request
from omnidim_ui.security import (
    CSRF_TOKEN,
    LOCAL_AUTH_TOKEN,
    compute_danger_signature,
    consume_confirm_token,
    delete_api_key,
    is_valid_csrf,
    is_valid_host,
    is_valid_origin,
    issue_confirm_token,
    redact_payload,
    save_api_key,
)


def parse_json_bytes(raw: bytes) -> Any:
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc


def is_read_only_active() -> bool:
    if getattr(config, "READ_ONLY_MODE", False):
        return True
    if "omnidim_ui" in sys.modules and getattr(sys.modules["omnidim_ui"], "READ_ONLY_MODE", False):
        return True
    if "server" in sys.modules and getattr(sys.modules["server"], "READ_ONLY_MODE", False):
        return True
    return False


class AppHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(405)
        self.send_header("Allow", "GET, POST, PUT, PATCH, DELETE")
        self.end_headers()

    def do_GET(self):
        self.route()

    def do_POST(self):
        self.route()

    def do_PUT(self):
        self.route()

    def do_PATCH(self):
        self.route()

    def do_DELETE(self):
        self.route()

    def log_message(self, fmt, *args):
        logger.info("%s - %s", self.address_string(), fmt % args)

    def is_authenticated(self) -> bool:
        token_hdr = self.headers.get("X-Local-Token", "").strip()
        if token_hdr and hmac.compare_digest(token_hdr, LOCAL_AUTH_TOKEN):
            return True
        cookie_hdr = self.headers.get("Cookie", "")
        if cookie_hdr:
            for item in cookie_hdr.split(";"):
                parts = item.strip().split("=", 1)
                if len(parts) == 2 and parts[0].strip() == "local_token":
                    if hmac.compare_digest(parts[1].strip(), LOCAL_AUTH_TOKEN):
                        return True
        return False

    def get_auth_session(self) -> str:
        token_hdr = self.headers.get("X-Local-Token", "").strip()
        if token_hdr:
            return token_hdr
        cookie_hdr = self.headers.get("Cookie", "")
        if cookie_hdr:
            for item in cookie_hdr.split(";"):
                parts = item.strip().split("=", 1)
                if len(parts) == 2 and parts[0].strip() == "local_token":
                    return parts[1].strip()
        return LOCAL_AUTH_TOKEN

    def route(self):
        req_id = uuid.uuid4().hex[:12]
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        try:
            if path.startswith("/api/"):
                # 1. Host header validation
                host_header = self.headers.get("Host", "")
                if not is_valid_host(host_header):
                    self.send_json(
                        {"ok": False, "error": "Invalid or forbidden Host header", "requestId": req_id},
                        status=403,
                    )
                    return

                # 2. Local auth token check
                if not self.is_authenticated():
                    self.send_json(
                        {
                            "ok": False,
                            "error": "Unauthorized: valid local auth token required in X-Local-Token header or cookie",
                            "requestId": req_id,
                        },
                        status=401,
                    )
                    return

                # 3. Read-only mode enforcement
                if is_read_only_active() and self.command != "GET":
                    self.send_json(
                        {
                            "ok": False,
                            "error": "Server is running in read-only mode. Mutating actions are blocked.",
                            "requestId": req_id,
                        },
                        status=403,
                    )
                    return

                # 4. Mutating requests validation (POST, PUT, PATCH, DELETE)
                if self.command in {"POST", "PUT", "PATCH"} or (
                    self.command == "DELETE" and int(self.headers.get("Content-Length", 0) or 0) > 0
                ):
                    content_type = self.headers.get("Content-Type", "")
                    if not content_type.lower().startswith("application/json"):
                        self.send_json(
                            {"ok": False, "error": "Content-Type must be application/json", "requestId": req_id},
                            status=415,
                        )
                        return

                    origin = self.headers.get("Origin", "")
                    if not is_valid_origin(origin):
                        self.send_json(
                            {"ok": False, "error": "Cross-origin request forbidden", "requestId": req_id},
                            status=403,
                        )
                        return

                    csrf_token = self.headers.get("X-CSRF-Token", "")
                    if not is_valid_csrf(csrf_token):
                        self.send_json(
                            {"ok": False, "error": "Invalid or missing CSRF token", "requestId": req_id},
                            status=403,
                        )
                        return

                self.route_api(path, parsed, req_id)
                return

            self.serve_static(path)

        except ValueError as exc:
            logger.warning("[%s] Validation error on %s %s: %s", req_id, self.command, path, exc)
            self.send_json({"ok": False, "error": str(exc), "requestId": req_id}, status=400)
        except Exception as exc:
            logger.exception("[%s] Internal server error on %s %s: %s", req_id, self.command, path, exc)
            self.send_json({"ok": False, "error": "Internal server error", "requestId": req_id}, status=500)

    def route_api(self, path: str, parsed: urllib.parse.ParseResult, req_id: str):
        if path == "/api/session" and self.command == "GET":
            self.send_json({"ok": True, "csrfToken": CSRF_TOKEN, "localToken": LOCAL_AUTH_TOKEN})
            return

        if path == "/api/health" and self.command == "GET":
            self.send_json(
                {
                    "ok": True,
                    "time": now_iso(),
                    "database": str(config.DB_PATH),
                    "endpointCount": len(ENDPOINTS),
                    "readOnly": is_read_only_active(),
                }
            )
            return

        if path == "/api/endpoints" and self.command == "GET":
            self.send_json({"ok": True, "groups": GROUPS, "endpoints": ENDPOINTS, "csrfToken": CSRF_TOKEN})
            return

        if path == "/api/settings":
            if self.command == "GET":
                self.send_json(read_settings())
                return
            if self.command in {"POST", "PUT"}:
                data = self.read_json()
                base_url = data.get("baseUrl", "").strip()
                api_key = data.get("apiKey", "").strip()
                retention_limit = data.get("retentionLimit")
                if base_url:
                    if not base_url.startswith("https://"):
                        raise ValueError("Base URL must start with https://")
                    save_setting("base_url", base_url.rstrip("/"))
                if api_key:
                    save_api_key(api_key)
                if retention_limit is not None:
                    try:
                        ret_int = int(retention_limit)
                        if ret_int < 10 or ret_int > 50000:
                            raise ValueError("Retention limit must be between 10 and 50,000")
                        save_setting("history_retention_limit", str(ret_int))
                    except (TypeError, ValueError) as exc:
                        raise ValueError(f"Invalid retention limit: {exc}") from exc
                self.send_json(read_settings())
                return
            if self.command == "DELETE":
                delete_api_key()
                self.send_json(read_settings())
                return

        if path == "/api/settings/api-key" and self.command == "DELETE":
            delete_api_key()
            self.send_json(read_settings())
            return

        if path == "/api/history":
            if self.command == "GET":
                query = urllib.parse.parse_qs(parsed.query)
                page = int(query.get("page", ["1"])[0])
                limit = int(query.get("limit", [query.get("pagesize", ["50"])[0]])[0])
                search = query.get("search", [None])[0]
                status = int(query.get("status")[0]) if "status" in query else None
                method = query.get("method", [None])[0]

                history_data = get_history(
                    page=page, limit=limit, search=search, status=status, method=method
                )
                # Keep backwards compatibility with {"records": [...]} while offering {"items": [...]}
                self.send_json({"ok": True, "records": history_data["items"], **history_data})
                return
            if self.command == "DELETE":
                clear_history()
                self.send_json({"ok": True, "message": "History cleared successfully"})
                return

        if path == "/api/history/clear" and self.command == "POST":
            clear_history()
            self.send_json({"ok": True, "message": "History cleared successfully"})
            return

        if path == "/api/saved-payloads":
            if self.command == "GET":
                query = urllib.parse.parse_qs(parsed.query)
                endpoint_filter = query.get("endpoint_id", [""])[0]
                with get_db() as conn:
                    if endpoint_filter:
                        rows = conn.execute(
                            "SELECT * FROM saved_payloads WHERE endpoint_id = ? ORDER BY updated_at DESC",
                            (endpoint_filter,),
                        ).fetchall()
                    else:
                        rows = conn.execute("SELECT * FROM saved_payloads ORDER BY updated_at DESC").fetchall()
                self.send_json({"records": [dict(row) for row in rows]})
                return
            if self.command == "POST":
                data = self.read_json()
                required = ["endpoint_id", "name", "method", "path"]
                missing = [key for key in required if not data.get(key)]
                if missing:
                    raise ValueError(f"Missing fields: {', '.join(missing)}")
                ts = now_iso()
                sanitized_query = redact_payload(data.get("query", {}))
                sanitized_body = redact_payload(data.get("body", {}))
                with get_db() as conn:
                    cur = conn.execute(
                        """
                        INSERT INTO saved_payloads
                        (endpoint_id, name, method, path, query_json, body_json, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            data["endpoint_id"],
                            data["name"],
                            data["method"],
                            data["path"],
                            compact_json(sanitized_query),
                            compact_json(sanitized_body),
                            ts,
                            ts,
                        ),
                    )
                self.send_json({"ok": True, "id": cur.lastrowid})
                return

        saved_match = re.fullmatch(r"/api/saved-payloads/(\d+)", path)
        if saved_match and self.command == "DELETE":
            with get_db() as conn:
                conn.execute("DELETE FROM saved_payloads WHERE id = ?", (int(saved_match.group(1)),))
            self.send_json({"ok": True})
            return

        if path == "/api/run" and self.command == "POST":
            self.run_omni_request(req_id)
            return

        self.send_json({"ok": False, "error": f"Unknown API endpoint: {path}", "requestId": req_id}, status=404)

    def run_omni_request(self, req_id: str):
        data = self.read_json()
        method = data.get("method", "GET").upper()
        path = data.get("path", "")
        query = data.get("query") or {}
        body = data.get("body", None)

        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("Unsupported HTTP method")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("Path must start with /")
        if "://" in path:
            raise ValueError("Path must be relative to the OmniDimension API base URL")
        if not isinstance(query, dict):
            raise ValueError("Query must be a JSON object")

        # 1. Match against registered endpoint allowlist
        matched_endpoint, _ = match_endpoint(method, path)
        if not matched_endpoint:
            self.send_json(
                {
                    "ok": False,
                    "error": f"Path '{path}' with method '{method}' is not in the registered API allowlist.",
                    "requestId": req_id,
                },
                status=403,
            )
            return

        endpoint_id_value = matched_endpoint["id"]

        # 2. Danger confirmation enforcement via single-use 60s bound token
        if matched_endpoint.get("danger"):
            sig = compute_danger_signature(method, path, query, body)
            confirm_token = str(data.get("confirmToken") or "").strip()
            session_id = self.get_auth_session()

            if not confirm_token:
                issued_token = issue_confirm_token(endpoint_id_value, sig, session_id=session_id)
                self.send_json(
                    {
                        "ok": False,
                        "danger": True,
                        "endpoint": matched_endpoint,
                        "requiredConfirm": matched_endpoint.get("summary", "Execute dangerous action"),
                        "confirmToken": issued_token,
                        "expiresInSeconds": 60,
                        "error": (
                            "Confirmation required: This dangerous action requires confirmation. "
                            "Resend the request with the provided single-use confirmToken within 60 seconds."
                        ),
                        "requestId": req_id,
                    },
                    status=428,
                )
                return

            token_ok, token_msg = consume_confirm_token(confirm_token, endpoint_id_value, sig, session_id=session_id)
            if not token_ok:
                new_token = issue_confirm_token(endpoint_id_value, sig, session_id=session_id)
                self.send_json(
                    {
                        "ok": False,
                        "danger": True,
                        "endpoint": matched_endpoint,
                        "requiredConfirm": matched_endpoint.get("summary", "Execute dangerous action"),
                        "confirmToken": new_token,
                        "expiresInSeconds": 60,
                        "error": f"Dangerous action confirmation rejected: {token_msg}",
                        "requestId": req_id,
                    },
                    status=428,
                )
                return

        settings = read_settings(include_secret=True)
        api_key = settings.get("apiKey", "")
        if not api_key:
            self.send_json(
                {
                    "ok": False,
                    "error": "Save your OmniDimension API key before sending requests.",
                    "requestId": req_id,
                },
                status=400,
            )
            return

        url = build_url(settings["baseUrl"], path, query)
        started = time.perf_counter()
        request_payload = {"method": method, "path": path, "query": query, "body": body}

        status, ok, response_payload = execute_proxy_request(
            method=method,
            url=url,
            api_key=api_key,
            body=body,
        )

        duration_ms = int((time.perf_counter() - started) * 1000)
        log_history(
            endpoint_id_value=endpoint_id_value,
            method=method,
            path=path,
            url=url,
            status=status or 0,
            ok=ok,
            duration_ms=duration_ms,
            request_payload=request_payload,
            response_payload=response_payload,
        )

        self.send_json(
            {
                "ok": ok,
                "status": status,
                "durationMs": duration_ms,
                "url": url,
                "data": response_payload,
            },
            status=200 if status is None or status < 500 else 502,
        )

    def read_json(self) -> Any:
        length_str = self.headers.get("Content-Length", "0")
        try:
            length = int(length_str)
        except ValueError as exc:
            raise ValueError("Invalid Content-Length header") from exc

        if length > MAX_REQUEST_BODY_BYTES:
            raise ValueError(f"Request body exceeds maximum allowed size ({MAX_REQUEST_BODY_BYTES} bytes)")
        return parse_json_bytes(self.rfile.read(length))

    def send_json(self, payload: dict, status: int = 200):
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for header, val in STATIC_SECURITY_HEADERS.items():
            self.send_header(header, val)
        self.end_headers()
        self.wfile.write(body)

    def serve_static(self, path: str):
        if path in {"", "/"}:
            file_path = (STATIC_DIR / "index.html").resolve()
        else:
            requested = path.lstrip("/")
            if requested.startswith("static/"):
                requested = requested[len("static/") :]
            file_path = (STATIC_DIR / requested).resolve()
            try:
                if not file_path.is_relative_to(STATIC_DIR.resolve()):
                    self.send_error(403)
                    return
            except (ValueError, AttributeError):
                self.send_error(403)
                return

            if not file_path.exists() or not file_path.is_file():
                file_path = (STATIC_DIR / "index.html").resolve()

        ctype, _ = mimetypes.guess_type(str(file_path))
        if not ctype:
            ctype = "text/plain; charset=utf-8"
        elif ctype.startswith("text/") or ctype in {"application/javascript", "application/json"}:
            ctype = f"{ctype}; charset=utf-8"

        try:
            content = file_path.read_bytes()
        except OSError:
            self.send_error(404)
            return

        if file_path.name == "index.html":
            html_text = content.decode("utf-8", errors="replace")
            meta_tags = (
                f'<meta name="csrf-token" content="{CSRF_TOKEN}">\n'
                f'    <meta name="local-token" content="{LOCAL_AUTH_TOKEN}">'
            )
            if '<meta name="csrf-token"' in html_text:
                html_text = re.sub(r'<meta name="csrf-token"[^>]*>', meta_tags, html_text)
            else:
                html_text = html_text.replace("</head>", f"    {meta_tags}\n  </head>")
            content = html_text.encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Set-Cookie",
            f"local_token={LOCAL_AUTH_TOKEN}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400",
        )
        for header, val in STATIC_SECURITY_HEADERS.items():
            self.send_header(header, val)
        self.end_headers()
        self.wfile.write(content)
