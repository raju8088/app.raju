import http.client
import json
import threading
from http.server import ThreadingHTTPServer

import pytest

import server


@pytest.fixture(scope="module")
def live_server():
    server.init_db()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.AppHandler)
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
        headers={"Host": "attacker.com", "X-Local-Token": server.LOCAL_AUTH_TOKEN},
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    conn.close()

    assert res.status == 403
    assert body["ok"] is False
    assert "Host" in body["error"]
    assert "requestId" in body


def test_host_header_allowed(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request(
        "GET",
        "/api/endpoints",
        headers={"Host": f"127.0.0.1:{port}", "X-Local-Token": server.LOCAL_AUTH_TOKEN},
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
        headers={"Host": f"127.0.0.1:{port}", "Cookie": f"local_token={server.LOCAL_AUTH_TOKEN}"},
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
        headers={"Host": f"127.0.0.1:{port}", "X-Local-Token": server.LOCAL_AUTH_TOKEN},
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
            "X-Local-Token": server.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": server.CSRF_TOKEN,
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
            "X-Local-Token": server.LOCAL_AUTH_TOKEN,
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
            "X-Local-Token": server.LOCAL_AUTH_TOKEN,
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
            "X-Local-Token": server.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": server.CSRF_TOKEN,
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
        headers={"Host": f"127.0.0.1:{port}", "X-Local-Token": server.LOCAL_AUTH_TOKEN},
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    conn.close()

    assert res.status == 200
    assert body["ok"] is True
    assert body["csrfToken"] == server.CSRF_TOKEN
    assert body["localToken"] == server.LOCAL_AUTH_TOKEN


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
    assert f'<meta name="csrf-token" content="{server.CSRF_TOKEN}">' in body
    assert f'<meta name="local-token" content="{server.LOCAL_AUTH_TOKEN}">' in body
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
    server.READ_ONLY_MODE = True
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
                "X-Local-Token": server.LOCAL_AUTH_TOKEN,
                "X-CSRF-Token": server.CSRF_TOKEN,
            },
        )
        res = conn.getresponse()
        body = json.loads(res.read().decode())
        conn.close()

        assert res.status == 403
        assert "read-only mode" in body["error"]
    finally:
        server.READ_ONLY_MODE = False


def test_sqlite_api_key_encrypted_at_rest():
    raw_key = "sk-test-secret-value-999888777"
    server.save_setting("api_key", raw_key)

    # 1. Check raw row in SQLite
    with server.get_db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = 'api_key'").fetchone()
        stored_raw = row["value"]
        assert stored_raw.startswith("enc:v1:")
        assert raw_key not in stored_raw

    # 2. Check get_api_key decrypts properly
    with pytest.MonkeyPatch.context() as mp:
        mp.delenv("OMNIDIM_API_KEY", raising=False)
        if server.keyring:
            mp.setattr(server.keyring, "get_password", lambda *args: None)
        retrieved_key, source = server.get_api_key()
        assert retrieved_key == raw_key
        assert source == "db"


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
            "Content-Length": str(server.MAX_REQUEST_BODY_BYTES + 1024),
            "Origin": f"http://127.0.0.1:{port}",
            "X-Local-Token": server.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": server.CSRF_TOKEN,
        },
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    conn.close()

    assert res.status == 400
    assert "maximum allowed size" in body["error"]
