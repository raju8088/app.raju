import http.client
import json
import threading
import urllib.parse
import uuid
from http.server import ThreadingHTTPServer

import pytest

import omnidim_ui


@pytest.fixture(scope="module")
def live_server():
    omnidim_ui.init_db()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), omnidim_ui.AppHandler)
    host, port = httpd.server_address
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"{host}:{port}", port
    httpd.shutdown()
    httpd.server_close()


def test_host_header_rejection(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request(
        "GET",
        "/api/endpoints",
        headers={"Host": "attacker.com", "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN},
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    conn.close()

    assert res.status == 403
    assert body["ok"] is False
    assert "Host" in body["error"]
    assert "requestId" in body


@pytest.mark.parametrize(
    "rebinding_host",
    [
        "127.0.0.1.attacker.com",
        "localhost.attacker.com",
        "attacker.com:8787",
        "127.0.0.1:8787@attacker.com",
        "127.0.0.1.nip.io",
        "127.0.0.1.xip.io",
        "spoofed-127.0.0.1",
        "localhost.evil.org:8787",
        "evil-127.0.0.1:8787",
        "subdomain.localhost.com",
    ],
)
def test_dns_rebinding_host_header_rejected(live_server, rebinding_host):
    host_port, port = live_server
    # Test validator function directly
    assert omnidim_ui.is_valid_host(rebinding_host) is False

    # Test HTTP handler rejection
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request(
        "GET",
        "/api/endpoints",
        headers={"Host": rebinding_host, "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN},
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    conn.close()

    assert res.status == 403
    assert body["ok"] is False
    assert "Host" in body["error"]


def test_host_header_allowed(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request(
        "GET",
        "/api/endpoints",
        headers={"Host": f"127.0.0.1:{port}", "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN},
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    conn.close()

    assert res.status == 200
    assert "groups" in body


def test_local_token_auth_missing_returns_401(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request("GET", "/api/endpoints", headers={"Host": f"127.0.0.1:{port}"})
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    conn.close()

    assert res.status == 401
    assert body["ok"] is False
    assert "Unauthorized" in body["error"]


def test_local_token_auth_invalid_returns_401(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request(
        "GET",
        "/api/endpoints",
        headers={"Host": f"127.0.0.1:{port}", "X-Local-Token": "invalid-token"},
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    conn.close()

    assert res.status == 401
    assert body["ok"] is False
    assert "Unauthorized" in body["error"]


def test_local_token_auth_via_cookie_succeeds(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request(
        "GET",
        "/api/endpoints",
        headers={"Host": f"127.0.0.1:{port}", "Cookie": f"local_token={omnidim_ui.LOCAL_AUTH_TOKEN}"},
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    conn.close()

    assert res.status == 200
    assert "groups" in body


def test_content_type_enforcement_on_mutating_requests(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)
    # Missing content-type on POST
    conn.request(
        "POST",
        "/api/settings",
        body=b'{"baseUrl":"https://omnidim.io/api/v1"}',
        headers={"Host": f"127.0.0.1:{port}", "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN},
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    conn.close()

    assert res.status == 415
    assert "Content-Type must be application/json" in body["error"]
    assert "requestId" in body


def test_origin_header_validation(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)
    # Invalid Origin
    conn.request(
        "POST",
        "/api/settings",
        body=b'{"baseUrl":"https://omnidim.io/api/v1"}',
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "Origin": "http://evil-attacker.com",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
        },
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    conn.close()

    assert res.status == 403
    assert "Cross-origin" in body["error"]


def test_csrf_token_enforcement(live_server):
    host_port, port = live_server

    # 1. Missing CSRF token
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request(
        "POST",
        "/api/settings",
        body=b'{"baseUrl":"https://omnidim.io/api/v1"}',
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "Origin": f"http://127.0.0.1:{port}",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
        },
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    conn.close()
    assert res.status == 403
    assert "CSRF" in body["error"]

    # 2. Invalid CSRF token
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request(
        "POST",
        "/api/settings",
        body=b'{"baseUrl":"https://omnidim.io/api/v1"}',
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "Origin": f"http://127.0.0.1:{port}",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": "bogus-csrf-token",
        },
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    conn.close()
    assert res.status == 403
    assert "CSRF" in body["error"]

    # 3. Valid CSRF token
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request(
        "POST",
        "/api/settings",
        body=b'{"baseUrl":"https://omnidim.io/api/v1"}',
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "Origin": f"http://127.0.0.1:{port}",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
        },
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    conn.close()
    assert res.status == 200
    assert body["baseUrl"] == "https://omnidim.io/api/v1"


def test_session_endpoint_returns_csrf_and_local_token(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request(
        "GET",
        "/api/session",
        headers={"Host": f"127.0.0.1:{port}", "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN},
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    conn.close()

    assert res.status == 200
    assert body["ok"] is True
    assert body["csrfToken"] == omnidim_ui.CSRF_TOKEN
    assert body["localToken"] == omnidim_ui.LOCAL_AUTH_TOKEN


def test_options_no_cors_headers(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request("OPTIONS", "/api/run", headers={"Host": f"127.0.0.1:{port}"})
    res = conn.getresponse()
    headers = dict(res.getheaders())
    conn.close()

    assert res.status in (405, 204)
    for header in headers:
        assert not header.lower().startswith("access-control-")


def test_static_security_headers_and_cookie_injection(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request("GET", "/", headers={"Host": f"127.0.0.1:{port}"})
    res = conn.getresponse()
    body = res.read().decode()
    opt = res.getheader("x-content-type-options")
    frame = res.getheader("x-frame-options")
    ref = res.getheader("referrer-policy")
    csp = res.getheader("content-security-policy")
    cookie = res.getheader("set-cookie")
    conn.close()

    assert res.status == 200
    assert opt == "nosniff"
    assert frame == "DENY"
    assert ref == "no-referrer"
    assert "default-src 'self'" in (csp or "")
    assert f'<meta name="csrf-token" content="{omnidim_ui.CSRF_TOKEN}">' in body
    assert f'<meta name="local-token" content="{omnidim_ui.LOCAL_AUTH_TOKEN}">' in body
    assert "HttpOnly" in (cookie or "")
    assert "SameSite=Strict" in (cookie or "")


def test_static_path_traversal_prevention(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request("GET", "/static/../../server.py", headers={"Host": f"127.0.0.1:{port}"})
    res = conn.getresponse()
    conn.close()

    # Must be rejected with 403 or 404, never 200 returning server.py
    assert res.status in (403, 404)


def test_read_only_mode_blocks_mutations(live_server):
    host_port, port = live_server
    omnidim_ui.READ_ONLY_MODE = True
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port)
        conn.request(
            "POST",
            "/api/settings",
            body=b'{"baseUrl":"https://omnidim.io/api/v1"}',
            headers={
                "Host": f"127.0.0.1:{port}",
                "Content-Type": "application/json",
                "Origin": f"http://127.0.0.1:{port}",
                "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
                "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
            },
        )
        res = conn.getresponse()
        body = json.loads(res.read().decode())
        conn.close()

        assert res.status == 403
        assert "read-only mode" in body["error"]
    finally:
        omnidim_ui.READ_ONLY_MODE = False


def test_sqlite_api_key_encrypted_at_rest():
    raw_key = "sk-test-secret-value-999888777"
    source = omnidim_ui.save_api_key(raw_key)

    if omnidim_ui.IS_WINDOWS:
        assert source == "dpapi"
        with omnidim_ui.get_db() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = 'api_key'").fetchone()
            stored_raw = row["value"]
            assert stored_raw.startswith("dpapi:")
            assert raw_key not in stored_raw

        with pytest.MonkeyPatch.context() as mp:
            mp.delenv("OMNIDIM_API_KEY", raising=False)
            retrieved_key, key_src = omnidim_ui.get_api_key()
            assert retrieved_key == raw_key
            assert key_src == "dpapi"
    elif omnidim_ui.security.keyring:
        assert source == "keyring"
        with pytest.MonkeyPatch.context() as mp:
            mp.delenv("OMNIDIM_API_KEY", raising=False)
            retrieved_key, key_src = omnidim_ui.get_api_key()
            assert retrieved_key == raw_key
            assert key_src == "keyring"


def test_migration_of_legacy_enc_v1():
    import hashlib
    import hmac
    import secrets

    secret_key = secrets.token_bytes(32)
    omnidim_ui.DATA_DIR.mkdir(parents=True, exist_ok=True)
    sec_file = omnidim_ui.DATA_DIR / ".secret_key"
    sec_file.write_bytes(secret_key)

    test_key = "legacy-secret-key-12345"
    nonce = secrets.token_bytes(16)
    k_enc = hmac.new(secret_key, b"ENC:" + nonce, hashlib.sha256).digest()
    k_mac = hmac.new(secret_key, b"MAC:" + nonce, hashlib.sha256).digest()
    plain_bytes = test_key.encode("utf-8")
    blocks = (len(plain_bytes) + 31) // 32
    keystream = b"".join(
        hmac.new(k_enc, i.to_bytes(4, "big"), hashlib.sha256).digest() for i in range(blocks)
    )
    ciphertext = bytes(p ^ k for p, k in zip(plain_bytes, keystream[: len(plain_bytes)], strict=True))
    tag = hmac.new(k_mac, nonce + ciphertext, hashlib.sha256).hexdigest()
    legacy_payload = f"enc:v1:{nonce.hex()}:{ciphertext.hex()}:{tag}"

    with omnidim_ui.get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('api_key', ?, ?)",
            (legacy_payload, omnidim_ui.now_iso()),
        )

    omnidim_ui.migrate_legacy_enc_v1()

    # Secret file should be cleaned up
    assert not sec_file.exists()

    # Migrated key should be readable
    with pytest.MonkeyPatch.context() as mp:
        mp.delenv("OMNIDIM_API_KEY", raising=False)
        migrated_key, _ = omnidim_ui.get_api_key()
        assert migrated_key == test_key


def test_request_body_size_limit(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)
    # Exceed 10MB limit with large Content-Length
    conn.request(
        "POST",
        "/api/settings",
        body=b"{}",
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "Content-Length": str(omnidim_ui.MAX_REQUEST_BODY_BYTES + 1024),
            "Origin": f"http://127.0.0.1:{port}",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
        },
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    conn.close()

    assert res.status == 400
    assert "maximum allowed size" in body["error"]


def test_request_history_redaction_secrets_not_persisted():
    # Sensitive canaries that should NEVER appear in plaintext in request_history
    canary_api_key = "canary-api-key-xyz-9876543210"
    canary_password = "canary-password-secret-12345"
    canary_auth_header = "Bearer canary-bearer-token-abcde"
    canary_sip_secret = "canary-sip-secret-pass-999"
    canary_token = "canary-jwt-token-abcdef123456"
    canary_query_val = "canary-url-query-secret-555"

    endpoint_test_id = f"test-redact-{uuid.uuid4().hex[:8]}"

    req_payload = {
        "api_key": canary_api_key,
        "nested": {
            "password": canary_password,
            "sip_password": canary_sip_secret,
            "safe_field": "keep-me-safe",
        },
        "items": [
            {"token": canary_token, "name": "item-1"},
        ],
    }

    res_payload = {
        "status": "success",
        "authorization": canary_auth_header,
        "result": {"api_token": canary_token},
    }

    raw_url = f"https://api.omnidim.io/v1/test?api_key={canary_query_val}&safe_param=hello"

    # Log to history
    omnidim_ui.log_history(
        endpoint_id_value=endpoint_test_id,
        method="POST",
        path="/v1/test",
        url=raw_url,
        status=200,
        ok=True,
        duration_ms=42,
        request_payload=req_payload,
        response_payload=res_payload,
    )

    # Query the SQLite request_history table directly
    with omnidim_ui.get_db() as conn:
        row = conn.execute(
            "SELECT url, request_json, response_json FROM request_history WHERE endpoint_id = ?",
            (endpoint_test_id,),
        ).fetchone()

    assert row is not None
    saved_url = row["url"]
    saved_req = row["request_json"]
    saved_res = row["response_json"]
    entire_record = f"{saved_url} {saved_req} {saved_res}"

    # Verify that NONE of the sensitive canaries are present in the database record
    all_canaries = [
        canary_api_key,
        canary_password,
        canary_auth_header,
        canary_sip_secret,
        canary_token,
        canary_query_val,
    ]
    for canary in all_canaries:
        assert canary not in entire_record, f"Secret canary '{canary}' leaked into request_history table!"

    # Verify that redactions were properly replaced with markers
    assert "[REDACTED]" in urllib.parse.unquote(saved_url)
    assert "[REDACTED]" in saved_req
    assert "[REDACTED]" in saved_res
    assert "keep-me-safe" in saved_req
