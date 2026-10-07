import http.client
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from omnidim_ui.config import PROXY_MAX_RETRIES, PROXY_RETRY_BACKOFF_FACTOR, PROXY_TIMEOUT_SECONDS
from omnidim_ui.logging_config import logger
from omnidim_ui.security import sanitize_url

MAX_UPSTREAM_RESPONSE_BYTES = 10 * 1024 * 1024


def validate_upstream_url(url: str) -> str:
    """Accept only the approved HTTPS API origin and an unambiguous API path."""
    if not isinstance(url, str) or not url or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise ValueError("Invalid upstream URL")
    try:
        parsed = urllib.parse.urlsplit(url)
        allowed = (
            parsed.scheme == "https" and parsed.hostname == "omnidim.io"
            and parsed.port in {None, 443} and not parsed.username and not parsed.password
            and not parsed.fragment and parsed.netloc.lower() in {"omnidim.io", "omnidim.io:443"}
        )
    except ValueError as exc:
        raise ValueError("Invalid upstream URL") from exc
    if not allowed:
        raise ValueError("Upstream URL must use https://omnidim.io/api/v1")
    if parsed.path != "/api/v1" and not parsed.path.startswith("/api/v1/"):
        raise ValueError("Upstream path must be under /api/v1")
    if any(c in parsed.path for c in ("%", "\\", "//")) or any(p in {".", ".."} for p in parsed.path.split("/")):
        raise ValueError("Upstream path contains ambiguous characters")
    return url


def build_url(base_url: str, path: str, query: dict[str, Any] | None) -> str:
    base = base_url.rstrip("/")
    parsed_pairs: list[tuple[str, Any]] = []
    for key, value in (query or {}).items():
        if value is None or value == "":
            continue
        if isinstance(value, list):
            parsed_pairs.extend((key, item) for item in value if item is not None and item != "")
        else:
            parsed_pairs.append((key, value))
    suffix = urllib.parse.urlencode(parsed_pairs, doseq=True)
    return f"{base}{path}" + (f"?{suffix}" if suffix else "")


def decode_response(raw: bytes | None, charset: str | None) -> Any:
    if not raw:
        return None
    try:
        text = raw.decode(charset or "utf-8", errors="replace")
    except LookupError:
        text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        # Never forward Authorization through a redirect, including same-origin redirects.
        return None


def _read_bounded(response: Any) -> bytes:
    length_header = response.headers.get("Content-Length")
    expected_length = None
    if isinstance(length_header, str):
        try:
            expected_length = int(length_header)
        except ValueError as exc:
            raise http.client.HTTPException("Invalid upstream response length") from exc
        if expected_length < 0:
            raise http.client.HTTPException("Invalid upstream response length")
        if expected_length > MAX_UPSTREAM_RESPONSE_BYTES:
            raise ValueError("Upstream response exceeds maximum allowed size")
    raw: bytes = response.read(MAX_UPSTREAM_RESPONSE_BYTES + 1)
    if len(raw) > MAX_UPSTREAM_RESPONSE_BYTES:
        raise ValueError("Upstream response exceeds maximum allowed size")
    if expected_length is not None and len(raw) < expected_length:
        raise http.client.IncompleteRead(raw)
    return raw


def execute_proxy_request(
    method: str,
    url: str,
    api_key: str,
    body: Any = None,
    timeout: int = PROXY_TIMEOUT_SECONDS,
    max_retries: int = PROXY_MAX_RETRIES,
    backoff_factor: float = PROXY_RETRY_BACKOFF_FACTOR,
    *,
    url_validator: Callable[[str], str] = validate_upstream_url,
    transport: Callable[..., Any] | None = None,
) -> tuple[int | None, bool, Any]:
    """Bound reads, refuse redirects, and retry GET only. Tests inject policy/transport explicitly."""
    url_validator(url)
    if not isinstance(api_key, str) or len(api_key) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in api_key):
        raise ValueError("Invalid API key")
    method = method.upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError("Unsupported HTTP method")
    is_idempotent = method == "GET"
    attempts_limit = max(1, min(int(max_retries), 5)) if is_idempotent else 1
    opener = transport or urllib.request.build_opener(NoRedirect()).open
    payload_bytes = None
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    if method != "GET" and body is not None:
        payload_bytes = json.dumps(body, allow_nan=False).encode("utf-8")
        headers["Content-Type"] = "application/json"

    for attempt in range(attempts_limit):
        try:
            req = urllib.request.Request(url, data=payload_bytes, headers=headers, method=method)
            with opener(req, timeout=timeout) as response:
                status = int(response.status)
                payload = decode_response(_read_bounded(response), response.headers.get_content_charset())
                return status, 200 <= status < 300, payload
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                payload = decode_response(_read_bounded(exc), exc.headers.get_content_charset())
            except ValueError:
                return None, False, {"error": "Upstream response exceeds maximum allowed size", "outcomeUnknown": not is_idempotent}
            except (http.client.HTTPException, OSError):
                return None, False, {"error": "Incomplete upstream response", "outcomeUnknown": not is_idempotent}
            finally:
                exc.close()
            if not (is_idempotent and status >= 500 and attempt < attempts_limit - 1):
                return status, False, payload
            logger.warning("Upstream HTTP %d on %s %s; retry %d/%d", status, method, sanitize_url(url), attempt + 1, attempts_limit)
        except (urllib.error.URLError, http.client.HTTPException, TimeoutError, ConnectionError, OSError):
            if not (is_idempotent and attempt < attempts_limit - 1):
                payload = {"error": "Network error", "detail": "The upstream service did not provide a complete response."}
                if not is_idempotent:
                    payload["outcomeUnknown"] = True
                return None, False, payload
            logger.warning("Upstream network failure on %s %s; retry %d/%d", method, sanitize_url(url), attempt + 1, attempts_limit)
        except ValueError:
            return None, False, {"error": "Upstream response exceeds maximum allowed size", "outcomeUnknown": not is_idempotent}
        time.sleep(min(max(backoff_factor, 0) * (2**attempt), 5))
    return None, False, {"error": "Upstream request failed"}
