"""Regression tests for production review findings. All upstream I/O is synthetic."""
import http.client
import io
import json
import threading
import urllib.error
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import pytest

from omnidim_ui import config, db, handlers, proxy, security
from omnidim_ui.__main__ import main
from omnidim_ui.endpoints import is_dangerous_operation, match_endpoint


@pytest.fixture
def local_app():
    server = ThreadingHTTPServer(("127.0.0.1", 0), handlers.AppHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    def request(path, payload=None, method="POST", extra_headers=None):
        headers = {"Host": f"127.0.0.1:{port}", "X-Local-Token": security.LOCAL_AUTH_TOKEN,
                   "X-CSRF-Token": security.CSRF_TOKEN, "Content-Type": "application/json"}
        headers.update(extra_headers or {})
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        body = payload if isinstance(payload, bytes) else json.dumps(payload or {}).encode()
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        conn.close()
        return response.status, json.loads(raw)

    yield request
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


@pytest.mark.parametrize("url", [
    "http://omnidim.io/api/v1", "https://evil.example/api/v1", "https://omnidim.io.evil.example/api/v1",
    "https://omnidim.io@evil.example/api/v1", "https://user:secret@omnidim.io/api/v1",
    "https://omnidim.io:444/api/v1", "https://omnidim.io/api/v1#secret", "https://omnidim.io/admin",
    "https://omnidim.io/api/v10/agents", "https://omnidim.io/api/v1/../admin", "https://omnidim.io/api/v1/%2e%2e/admin",
    "https://omnidim.io/api/v1//agents", "https://omnidim.io/api/v1\\agents", "https://omnidim.io/api/v1\n",
    "https://omnidim.io:invalid/api/v1",
])
def test_credential_destination_allowlist(url):
    transport = mock.Mock()
    with pytest.raises(ValueError):
        proxy.execute_proxy_request("GET", url, "never-send-this", transport=transport)
    transport.assert_not_called()


def test_approved_upstream_and_unicode_response():
    assert proxy.validate_upstream_url("https://omnidim.io/api/v1/agents?page=1")
    assert proxy.decode_response(b'{"ok":true}', "unknown-encoding") == {"ok": True}


@pytest.mark.parametrize("payload", [b"[]", b"null", b"12", b'"text"', b'{"value": NaN}', b'{"value": Infinity}', b'\xff'])
def test_json_envelope_requires_finite_object(local_app, payload):
    status, _ = local_app("/api/run", payload)
    assert status == 400


@pytest.mark.parametrize("payload", [
    {"method": 12, "path": "/agents"}, {"method": "GET", "path": 12},
    {"method": "GET", "path": "/agents", "query": []},
    {"method": "GET", "path": "/agents", "query": {"p": {"nested": "value"}}},
    {"method": "POST", "path": "/agents/create", "body": []},
    {"method": "GET", "path": "/agents", "confirmToken": 12},
    {"method": "GET", "path": "/agents/%2e%2e"},
    {"method": "GET", "path": "/agents/abc%2fdef"},
])
def test_request_type_and_path_validation(local_app, payload):
    status, _ = local_app("/api/run", payload)
    assert status == 400


def test_framing_and_delete_csrf(local_app):
    assert local_app("/api/settings", b"", extra_headers={"Content-Length": "-1"})[0] == 400
    assert local_app("/api/settings", b"", extra_headers={"Content-Length": "invalid"})[0] == 400
    assert local_app("/api/settings", b"", extra_headers={"Transfer-Encoding": "chunked"})[0] == 400
    for route in ("/api/history", "/api/settings/api-key", "/api/saved-payloads/1"):
        status, _ = local_app(route, b"", method="DELETE", extra_headers={"X-CSRF-Token": ""})
        assert status == 403


def test_preflight_never_executes_and_resume_is_protected(local_app, monkeypatch):
    upstream = mock.Mock(return_value=(201, True, {"created": True}))
    monkeypatch.setattr(handlers, "execute_proxy_request", upstream)
    security.save_api_key("synthetic-test-key")
    safe = {"method": "POST", "path": "/agents/create", "body": {"name": "Preview only"}}
    status, data = local_app("/api/preflight", safe)
    assert status == 200 and data["danger"] is False
    upstream.assert_not_called()
    request = {"method": "PUT", "path": "/calls/bulk_call/123", "body": {"action": "resume"}}
    status, data = local_app("/api/preflight", request)
    assert status == 200 and data["danger"] is True and data["confirmToken"]
    upstream.assert_not_called()
    assert local_app("/api/run", request)[0] == 428
    confirmed = {**request, "confirmToken": data["confirmToken"]}
    assert local_app("/api/run", confirmed)[0] == 200
    assert upstream.call_count == 1
    assert local_app("/api/run", confirmed)[0] == 428
    assert upstream.call_count == 1
    endpoint, _ = match_endpoint("PUT", "/calls/bulk_call/123/numbers/12")
    assert endpoint["danger"] and is_dangerous_operation(endpoint, {"is_active": True})


def test_read_only_allows_upstream_reads(local_app, monkeypatch):
    security.save_api_key("synthetic-test-key")
    monkeypatch.setattr(config, "READ_ONLY_MODE", True)
    upstream = mock.Mock(return_value=(200, True, []))
    monkeypatch.setattr(handlers, "execute_proxy_request", upstream)
    assert local_app("/api/run", {"method": "GET", "path": "/agents"})[0] == 200
    assert local_app("/api/preflight", {"method": "GET", "path": "/agents"})[0] == 200
    assert local_app("/api/run", {"method": "POST", "path": "/agents/create", "body": {}})[0] == 403
    assert local_app("/api/preflight", {"method": "POST", "path": "/agents/create", "body": {}})[0] == 403
    assert upstream.call_count == 1


def test_success_survives_history_failure_and_maps_upstream_errors(local_app, monkeypatch):
    security.save_api_key("synthetic-test-key")
    upstream = mock.Mock(return_value=(201, True, {"id": 123}))
    monkeypatch.setattr(handlers, "execute_proxy_request", upstream)
    monkeypatch.setattr(handlers, "log_history", mock.Mock(side_effect=OSError("disk full")))
    status, result = local_app("/api/run", {"method": "POST", "path": "/agents/create", "body": {}})
    assert status == 200 and result["ok"] is True and result["historySaved"] is False
    assert upstream.call_count == 1
    for upstream_status, client_status in [(401, 401), (404, 404), (429, 429), (503, 502), (None, 502), (302, 502)]:
        upstream.return_value = upstream_status, False, {"error": "synthetic failure"}
        status, result = local_app("/api/run", {"method": "GET", "path": "/agents"})
        assert status == client_status and result["ok"] is False


def test_saved_payload_is_complete_beyond_history_limit(local_app):
    content = "x" * (config.MAX_LOG_CHARS + 200)
    payload = {"endpoint_id": "post-agents-create", "name": "Long instructions", "method": "POST", "path": "/agents/create",
               "query": {}, "body": {"instructions": content, "apiKey": "must-redact"}}
    status, result = local_app("/api/saved-payloads", payload)
    assert status == 200
    with db.get_db() as conn:
        row = conn.execute("SELECT body_json FROM saved_payloads WHERE id = ?", (result["id"],)).fetchone()
    saved = json.loads(row["body_json"])
    assert saved["instructions"] == content
    assert saved["apiKey"] == "[REDACTED]"
    with pytest.raises(ValueError, match="maximum allowed"):
        db.saved_json({"text": "x" * config.MAX_REQUEST_BODY_BYTES})


def test_redaction_is_case_separator_insensitive_and_drops_url_userinfo():
    payload = {"apiKey": "aaa", "Api-Key": "bbb", "clientSecret": "ccc", "credentials": "ddd", "cookie": "eee"}
    assert set(security.redact_payload(payload).values()) == {"[REDACTED]"}
    sanitized = security.sanitize_url("https://user:password@omnidim.io/api/v1?apiKey=abc&limit=2#token")
    assert "user" not in sanitized and "password" not in sanitized and "abc" not in sanitized and "token" not in sanitized
    assert "limit=2" in sanitized


def test_confirmation_cannot_omit_session_binding():
    token = security.issue_confirm_token("endpoint", "signature", session_id="session-one")
    assert security.consume_confirm_token(token, "endpoint", "signature", session_id="")[0] is False


def test_cli_refuses_public_bind_and_custom_database_used(tmp_path):
    for host in ("0.0.0.0", "192.168.1.1", "::"):
        with pytest.raises(SystemExit):
            main(["--host", host])
    custom = tmp_path / "custom" / "chosen.sqlite3"
    with mock.patch("omnidim_ui.__main__.ThreadingHTTPServer"):
        assert main(["--db", str(custom)]) == 0
    db.save_setting("proof", "uses-custom")
    with db.get_db(custom) as conn:
        assert conn.execute("SELECT value FROM settings WHERE key = 'proof'").fetchone()[0] == "uses-custom"


def test_redirect_never_forwards_credentials():
    visits = []

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            visits.append((self.path, self.headers.get("Authorization")))
            self.send_response(302)
            self.send_header("Location", "/credential-sink")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/redirect"
    try:
        status, ok, _ = proxy.execute_proxy_request("GET", url, "fake-secret", url_validator=lambda value: value)
        assert status == 302 and ok is False
        assert visits == [("/redirect", "Bearer fake-secret")]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("error_response", [False, True])
def test_upstream_read_is_bounded(error_response, monkeypatch):
    monkeypatch.setattr(proxy, "MAX_UPSTREAM_RESPONSE_BYTES", 128)
    message = Message()
    message["Content-Type"] = "application/json"
    if error_response:
        error = urllib.error.HTTPError("https://omnidim.io/api/v1/agents", 500, "Error", message, io.BytesIO(b"x" * 129))
        transport = mock.Mock(side_effect=error)
    else:
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = b"x" * 129
        response.headers = message
        transport = mock.Mock(return_value=response)
    status, ok, data = proxy.execute_proxy_request("POST", "https://omnidim.io/api/v1/agents/create", "fake-key", transport=transport)
    assert status is None and ok is False and data["outcomeUnknown"] is True
    assert transport.call_count == 1
    if not error_response:
        response.read.assert_called_once_with(129)


def test_mutation_network_outcome_unknown_and_get_retries():
    transport = mock.Mock(side_effect=TimeoutError("private credential should not leak"))
    status, ok, data = proxy.execute_proxy_request("POST", "https://omnidim.io/api/v1/agents/create", "fake-key", transport=transport)
    assert status is None and ok is False and data["outcomeUnknown"] is True
    assert "credential" not in json.dumps(data)
    assert transport.call_count == 1
    transport.reset_mock()
    with mock.patch("omnidim_ui.proxy.time.sleep"):
        proxy.execute_proxy_request("GET", "https://omnidim.io/api/v1/agents", "fake-key", transport=transport, max_retries=3)
    assert transport.call_count == 3

@pytest.mark.parametrize("error_response", [False, True])
def test_incomplete_mutation_response_keeps_unknown_outcome(error_response):
    headers = Message()
    headers["Content-Type"] = "application/json"
    headers["Content-Length"] = "100"
    if error_response:
        response = urllib.error.HTTPError("https://omnidim.io/api/v1/agents", 500, "Error", headers, io.BytesIO(b"{}"))
        transport = mock.Mock(side_effect=response)
    else:
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 201
        response.headers = headers
        response.read.return_value = b"{}"
        transport = mock.Mock(return_value=response)
    status, ok, result = proxy.execute_proxy_request("POST", "https://omnidim.io/api/v1/agents/create", "fake", transport=transport)
    assert status is None and ok is False and result["outcomeUnknown"] is True
    assert transport.call_count == 1


def test_api_key_header_injection_rejected():
    transport = mock.Mock()
    with pytest.raises(ValueError, match="Invalid API key"):
        proxy.execute_proxy_request("GET", "https://omnidim.io/api/v1/agents", "key\r\nX-Custom: injected", transport=transport)
    transport.assert_not_called()


def test_windows_secret_storage_with_injected_crypto(monkeypatch):
    # Exercise Windows storage orchestration without touching the user's native DPAPI/keyring.
    monkeypatch.setattr(security, "IS_WINDOWS", True)
    monkeypatch.setattr(security, "dpapi_protect", mock.Mock(return_value="dpapi:c3ludGhldGlj"))
    monkeypatch.setattr(security, "dpapi_unprotect", mock.Mock(return_value="synthetic-only"))
    assert security.save_api_key("synthetic-only") == "dpapi"
    with db.get_db() as conn:
        encrypted = conn.execute("SELECT value FROM settings WHERE key = 'api_key'").fetchone()[0]
        assert encrypted.startswith("dpapi:") and "synthetic-only" not in encrypted
    assert security.get_api_key() == ("synthetic-only", "dpapi")
    security.dpapi_unprotect.side_effect = ValueError("invalid synthetic cipher")
    assert security.get_api_key() == ("", "none")
