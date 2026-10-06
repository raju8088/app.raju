import http.client
import json
import threading
import time
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


def test_extra_endpoints_marked_as_danger():
    danger_endpoints = {ep["path"]: ep for ep in server.ENDPOINTS if ep.get("danger")}

    # Requirements: phone number import (twilio, exotel, sip), add user, user access control,
    # user expiry, child concurrency, add contacts (bulk and single), KYC submit.
    assert "/phone_number/import/twilio" in danger_endpoints
    assert "/phone_number/import/exotel" in danger_endpoints
    assert "/phone_number/import/sip" in danger_endpoints
    assert "/reseller/users/add" in danger_endpoints
    assert "/reseller/users/access-control" in danger_endpoints
    assert "/reseller/users/expiry" in danger_endpoints
    assert "/reseller/concurrency" in danger_endpoints
    assert "/calls/bulk_call/{campaign_id}/add_contact" in danger_endpoints
    assert "/calls/bulk_call/{campaign_id}/add_contacts" in danger_endpoints
    assert "/reseller/kyc/steps/{step}" in danger_endpoints


def test_allowlist_rejects_unregistered_paths(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps({"method": "POST", "path": "/unregistered/arbitrary/proxy", "body": {}}).encode(),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": server.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": server.CSRF_TOKEN,
        },
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    conn.close()

    assert res.status == 403
    assert body["ok"] is False
    assert "not in the registered API allowlist" in body["error"]


def test_danger_enforcement_returns_428_without_confirm(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)
    # /calls/dispatch is a dangerous action
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps({"method": "POST", "path": "/calls/dispatch", "body": {}}).encode(),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": server.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": server.CSRF_TOKEN,
        },
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    conn.close()

    assert res.status == 428
    assert body["ok"] is False
    assert body["danger"] is True
    assert "confirmation" in body["error"]
    assert body["requiredConfirm"] == "Dispatch call"
    assert "confirmToken" in body


def test_danger_single_use_token_accepted_and_consumed(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)

    # 1. First request triggers 428 and returns confirmToken
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps({"method": "POST", "path": "/calls/dispatch", "body": {}}).encode(),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": server.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": server.CSRF_TOKEN,
        },
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    assert res.status == 428
    confirm_token = body["confirmToken"]

    # 2. Second request uses token; fails with 400 (API key needed) not 428 (danger check passed!)
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps({
            "method": "POST",
            "path": "/calls/dispatch",
            "body": {},
            "confirmToken": confirm_token,
        }).encode(),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": server.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": server.CSRF_TOKEN,
        },
    )
    res2 = conn.getresponse()
    body2 = json.loads(res2.read().decode())
    # Passed danger check, reached API key check
    assert res2.status in (400, 200, 502)
    assert res2.status != 428
    assert "ok" in body2


    # 3. Third request tries to reuse same token -> rejected with 428 (token already consumed!)
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps({
            "method": "POST",
            "path": "/calls/dispatch",
            "body": {},
            "confirmToken": confirm_token,
        }).encode(),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": server.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": server.CSRF_TOKEN,
        },
    )
    res3 = conn.getresponse()
    assert res3.status == 428
    conn.close()


def test_danger_tampered_body_fails(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)

    # 1. Request token for initial body
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps({"method": "POST", "path": "/calls/dispatch", "body": {"to_number": "+15551234567"}}).encode(),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": server.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": server.CSRF_TOKEN,
        },
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    assert res.status == 428
    token = body["confirmToken"]

    # 2. Try to submit with tampered body
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps({
            "method": "POST",
            "path": "/calls/dispatch",
            "body": {"to_number": "+15559999999"},  # Altered number!
            "confirmToken": token,
        }).encode(),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": server.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": server.CSRF_TOKEN,
        },
    )
    res2 = conn.getresponse()
    body2 = json.loads(res2.read().decode())
    conn.close()

    assert res2.status == 428
    assert "modified after confirmation token was issued" in body2["error"]


def test_danger_bypass_flags_rejected(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)

    # 1. confirmed: true without token
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps({
            "method": "POST",
            "path": "/calls/dispatch",
            "body": {},
            "confirmed": True,
        }).encode(),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": server.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": server.CSRF_TOKEN,
        },
    )
    res = conn.getresponse()
    assert res.status == 428

    # 2. confirm phrase without token
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps({
            "method": "POST",
            "path": "/calls/dispatch",
            "body": {},
            "confirm": "Dispatch call",
        }).encode(),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": server.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": server.CSRF_TOKEN,
        },
    )
    res2 = conn.getresponse()
    conn.close()
    assert res2.status == 428


def test_danger_token_reused_after_use(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)

    payload = {
        "method": "POST",
        "path": "/calls/dispatch",
        "body": {"to_number": "+15550001111"},
    }

    # 1. First call without token generates token
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps(payload).encode(),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": server.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": server.CSRF_TOKEN,
        },
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    assert res.status == 428
    token = body["confirmToken"]

    # 2. First execution with token consumes it
    payload_with_token = dict(payload)
    payload_with_token["confirmToken"] = token
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps(payload_with_token).encode(),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": server.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": server.CSRF_TOKEN,
        },
    )
    res2 = conn.getresponse()
    # It must not return 428 (danger check passed and token consumed)
    assert res2.status in (200, 400, 502)

    # 3. Second execution with the EXACT same token must fail with 428
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps(payload_with_token).encode(),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": server.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": server.CSRF_TOKEN,
        },
    )
    res3 = conn.getresponse()
    body3 = json.loads(res3.read().decode())
    conn.close()

    assert res3.status == 428
    assert "already-used" in body3["error"] or "already been used" in body3["error"]


def test_danger_token_expired(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)

    payload = {
        "method": "POST",
        "path": "/calls/dispatch",
        "body": {"to_number": "+15550002222"},
    }

    # 1. First call generates token
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps(payload).encode(),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": server.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": server.CSRF_TOKEN,
        },
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    assert res.status == 428
    token = body["confirmToken"]

    # 2. Fast forward token creation time past CONFIRMATION_TOKEN_TTL (60s)
    created_at, ep_id, sig, *rest = server.CONFIRMATION_TOKENS[token]
    sess = rest[0] if rest else ""
    server.CONFIRMATION_TOKENS[token] = (time.time() - 75, ep_id, sig, sess)

    # 3. Request with expired token should be rejected with 428
    payload_with_token = dict(payload)
    payload_with_token["confirmToken"] = token
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps(payload_with_token).encode(),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": server.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": server.CSRF_TOKEN,
        },
    )
    res2 = conn.getresponse()
    body2 = json.loads(res2.read().decode())
    conn.close()

    assert res2.status == 428
    assert "expired" in body2["error"].lower()




def test_path_parameter_character_rejection():
    # Attempt path traversal in path parameter
    with pytest.raises(ValueError, match="illegal characters"):
        server.match_endpoint("GET", "/agents/../secret")

    with pytest.raises(ValueError, match="illegal characters"):
        server.match_endpoint("GET", "/agents/123?query=1")

    with pytest.raises(ValueError, match="illegal characters"):
        server.match_endpoint("GET", "/agents/123#fragment")

    with pytest.raises(ValueError, match="illegal characters"):
        server.match_endpoint("GET", "/agents/123\x00bad")


def test_path_parameter_matching_valid():
    ep, params = server.match_endpoint("GET", "/agents/158910")
    assert ep is not None
    assert ep["path"] == "/agents/{agent_id}"
    assert params["agent_id"] == "158910"

    ep_multi, params_multi = server.match_endpoint("PATCH", "/agents/42/versions/3")
    assert ep_multi is not None
    assert ep_multi["path"] == "/agents/{agent_id}/versions/{version_number}"
    assert params_multi["agent_id"] == "42"
    assert params_multi["version_number"] == "3"


def test_confirmation_token_concurrent_consumption():
    sig = server.compute_danger_signature("POST", "/calls/dispatch", {}, {"num": 1})
    token = server.issue_confirm_token("post-calls-dispatch", sig, session_id="test-session")

    results = []
    barrier = threading.Barrier(20)

    def worker():
        barrier.wait()
        res = server.consume_confirm_token(token, "post-calls-dispatch", sig, session_id="test-session")
        results.append(res)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly 1 thread must succeed; 19 must fail
    successes = [r for r in results if r[0] is True]
    failures = [r for r in results if r[0] is False]
    assert len(successes) == 1
    assert len(failures) == 19
    assert all("Invalid, expired, or already-used" in f[1] for f in failures)


def test_confirmation_token_purged_on_access():
    old_token = "expired-token-canary-12345"
    with server.security.TOKEN_LOCK:
        server.CONFIRMATION_TOKENS[old_token] = (
            time.time() - 120,
            "ep-test",
            "dummy-sig",
            "dummy-session",
        )

    # Issue a new token - this triggers access and purge
    new_sig = server.compute_danger_signature("POST", "/calls/dispatch", {}, {})
    new_token = server.issue_confirm_token("ep-test", new_sig, session_id="sess")

    # Verify expired token was purged from dictionary
    assert old_token not in server.CONFIRMATION_TOKENS
    assert new_token in server.CONFIRMATION_TOKENS


def test_confirmation_token_session_binding():
    sig = server.compute_danger_signature("POST", "/calls/dispatch", {}, {})

    # 1. Token issued for Alice is rejected when presented by Bob's session
    token_alice = server.issue_confirm_token("ep-test", sig, session_id="session-user-alice")
    ok_bob, msg_bob = server.consume_confirm_token(token_alice, "ep-test", sig, session_id="session-user-bob")
    assert ok_bob is False
    assert "different local session" in msg_bob

    # 2. Token issued for Alice is accepted when presented by Alice's session
    token_valid = server.issue_confirm_token("ep-test", sig, session_id="session-user-alice")
    ok_alice, msg_alice = server.consume_confirm_token(token_valid, "ep-test", sig, session_id="session-user-alice")
    assert ok_alice is True
    assert msg_alice == "ok"

