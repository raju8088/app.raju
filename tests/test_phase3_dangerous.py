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
