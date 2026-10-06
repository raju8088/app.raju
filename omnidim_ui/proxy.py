import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from omnidim_ui.config import (
    PROXY_MAX_RETRIES,
    PROXY_RETRY_BACKOFF_FACTOR,
    PROXY_TIMEOUT_SECONDS,
)
from omnidim_ui.logging_config import logger


def build_url(base_url: str, path: str, query: dict[str, Any] | None) -> str:
    base = base_url.rstrip("/")
    parsed_pairs = []
    for key, value in (query or {}).items():
        if value is None or value == "":
            continue
        if isinstance(value, list):
            for item in value:
                if item is not None and item != "":
                    parsed_pairs.append((key, item))
        else:
            parsed_pairs.append((key, value))
    suffix = urllib.parse.urlencode(parsed_pairs, doseq=True)
    return f"{base}{path}" + (f"?{suffix}" if suffix else "")


def decode_response(raw: bytes | None, charset: str | None) -> Any:
    if not raw:
        return None
    text = raw.decode(charset or "utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def execute_proxy_request(
    method: str,
    url: str,
    api_key: str,
    body: Any = None,
    timeout: int = PROXY_TIMEOUT_SECONDS,
    max_retries: int = PROXY_MAX_RETRIES,
    backoff_factor: float = PROXY_RETRY_BACKOFF_FACTOR,
) -> tuple[int | None, bool, Any]:
    """Execute proxy request to upstream OmniDimension API.

    Idempotent GET requests are automatically retried on 5xx or transient network
    failures with exponential backoff. Mutating requests (POST, PUT, PATCH, DELETE)
    are NEVER retried to prevent unintended side effects.
    """
    method = method.upper()
    is_idempotent = method == "GET"
    attempts_limit = max_retries if is_idempotent else 1

    payload_bytes = None
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    if method != "GET" and body is not None:
        payload_bytes = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    status = None
    ok = False
    response_payload = None

    for attempt in range(attempts_limit):
        try:
            req = urllib.request.Request(url, data=payload_bytes, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=timeout) as response:
                status = response.status
                raw = response.read()
                response_payload = decode_response(raw, response.headers.get_content_charset())
                ok = 200 <= status < 300
                return status, ok, response_payload

        except urllib.error.HTTPError as exc:
            status = exc.code
            raw = exc.read()
            response_payload = decode_response(raw, exc.headers.get_content_charset())
            ok = False

            # Only retry idempotent GET on 5xx server errors
            if is_idempotent and status >= 500 and attempt < attempts_limit - 1:
                sleep_sec = backoff_factor * (2**attempt)
                logger.warning(
                    "Upstream 5xx error (%d) on %s %s. Retrying in %.2fs (attempt %d/%d)...",
                    status,
                    method,
                    url,
                    sleep_sec,
                    attempt + 1,
                    attempts_limit,
                )
                time.sleep(sleep_sec)
                continue
            return status, ok, response_payload

        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            status = None
            ok = False
            detail = str(getattr(exc, "reason", exc))
            response_payload = {"error": "Network error", "detail": detail}

            if is_idempotent and attempt < attempts_limit - 1:
                sleep_sec = backoff_factor * (2**attempt)
                logger.warning(
                    "Network error (%s) on %s %s. Retrying in %.2fs (attempt %d/%d)...",
                    detail,
                    method,
                    url,
                    sleep_sec,
                    attempt + 1,
                    attempts_limit,
                )
                time.sleep(sleep_sec)
                continue
            return status, ok, response_payload

    return status, ok, response_payload
