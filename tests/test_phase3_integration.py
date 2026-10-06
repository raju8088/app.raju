"""Integration tests for OmniDimension Control Center with Stub Upstream Server."""

from __future__ import annotations

import http.client
import json
import threading
from http.server import ThreadingHTTPServer

import pytest

import omnidim_ui
from tests.mock_upstream import StubUpstreamServer


@pytest.fixture(scope="module")
def stub_upstream():
    server = StubUpstreamServer()
    base_url = server.start()
    yield base_url
    server.stop()


@pytest.fixture(scope="module")
def integration_app(stub_upstream):
    omnidim_ui.init_db()
    # Configure base URL and API key
    omnidim_ui.save_setting("base_url", f"{stub_upstream}/v1")
    omnidim_ui.save_api_key("sk-test-valid-integration-key-42")

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), omnidim_ui.AppHandler)
    host, port = httpd.server_address
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"{host}:{port}", port
    httpd.shutdown()
    httpd.server_close()


def test_proxy_get_agents_integration(integration_app):
    host_port, port = integration_app
    conn = http.client.HTTPConnection("127.0.0.1", port)

    conn.request(
        "POST",
        "/api/run",
        body=json.dumps({"method": "GET", "path": "/agents"}).encode("utf-8"),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
        },
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode("utf-8"))
    conn.close()

    assert res.status == 200
    assert body["ok"] is True
    assert body["status"] == 200
    data = body["data"]
    assert "agents" in data
    assert any(a["id"] == "158910" for a in data["agents"])


def test_proxy_post_create_agent_integration(integration_app):
    host_port, port = integration_app
    conn = http.client.HTTPConnection("127.0.0.1", port)

    conn.request(
        "POST",
        "/api/run",
        body=json.dumps({
            "method": "POST",
            "path": "/agents/create",
            "body": {"name": "Integration Bot", "voice": "shimmer"},
        }).encode("utf-8"),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
        },
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode("utf-8"))
    conn.close()

    assert res.status == 200
    assert body["ok"] is True
    assert body["status"] == 201
    assert body["data"]["name"] == "Integration Bot"


def test_proxy_put_agent_integration(integration_app):
    host_port, port = integration_app
    conn = http.client.HTTPConnection("127.0.0.1", port)

    conn.request(
        "POST",
        "/api/run",
        body=json.dumps({
            "method": "PUT",
            "path": "/agents/158910",
            "body": {"name": "Updated Rep Name"},
        }).encode("utf-8"),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
        },
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode("utf-8"))
    conn.close()

    assert res.status == 200
    assert body["ok"] is True
    assert body["data"]["name"] == "Updated Rep Name"


def test_proxy_delete_agent_danger_integration(integration_app):
    host_port, port = integration_app
    conn = http.client.HTTPConnection("127.0.0.1", port)

    # 1. Step 1: DELETE is danger endpoint -> 428 and token
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps({
            "method": "DELETE",
            "path": "/agents/agent-1",
        }).encode("utf-8"),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
        },
    )
    res1 = conn.getresponse()
    body1 = json.loads(res1.read().decode("utf-8"))
    assert res1.status == 428
    token = body1["confirmToken"]

    # 2. Step 2: Pass token to execute
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps({
            "method": "DELETE",
            "path": "/agents/agent-1",
            "confirmToken": token,
        }).encode("utf-8"),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
        },
    )
    res2 = conn.getresponse()
    body2 = json.loads(res2.read().decode("utf-8"))
    conn.close()

    assert res2.status == 200
    assert body2["ok"] is True
    assert body2["data"]["deleted"] is True


def test_proxy_danger_dispatch_call_flow_integration(integration_app):
    host_port, port = integration_app
    conn = http.client.HTTPConnection("127.0.0.1", port)

    payload = {
        "method": "POST",
        "path": "/calls/dispatch",
        "body": {"to_number": "+15553334444"},
    }

    # Step 1: Request without token triggers 428 and issues confirmation token
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps(payload).encode("utf-8"),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
        },
    )
    res1 = conn.getresponse()
    body1 = json.loads(res1.read().decode("utf-8"))
    assert res1.status == 428
    assert body1["danger"] is True
    token = body1["confirmToken"]

    # Step 2: Request with confirmed token executes upstream call dispatch
    confirmed_payload = dict(payload)
    confirmed_payload["confirmToken"] = token

    conn.request(
        "POST",
        "/api/run",
        body=json.dumps(confirmed_payload).encode("utf-8"),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
        },
    )
    res2 = conn.getresponse()
    body2 = json.loads(res2.read().decode("utf-8"))
    conn.close()

    assert res2.status == 200
    assert body2["ok"] is True
    assert body2["data"]["status"] == "queued"
    assert body2["data"]["to_number"] == "+15553334444"


def test_proxy_danger_phone_import_integration(integration_app):
    host_port, port = integration_app
    conn = http.client.HTTPConnection("127.0.0.1", port)

    payload = {
        "method": "POST",
        "path": "/phone_number/import/twilio",
        "body": {"sid": "AC123456789"},
    }

    # 1. Step 1: 428
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps(payload).encode("utf-8"),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
        },
    )
    res1 = conn.getresponse()
    body1 = json.loads(res1.read().decode("utf-8"))
    assert res1.status == 428
    token = body1["confirmToken"]

    # 2. Step 2: Execute with token
    payload_conf = dict(payload)
    payload_conf["confirmToken"] = token
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps(payload_conf).encode("utf-8"),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
        },
    )
    res2 = conn.getresponse()
    body2 = json.loads(res2.read().decode("utf-8"))
    conn.close()

    assert res2.status == 200
    assert body2["ok"] is True
    assert body2["data"]["imported"] is True
    assert body2["data"]["provider"] == "twilio"


def test_proxy_upstream_error_codes(integration_app):
    host_port, port = integration_app
    conn = http.client.HTTPConnection("127.0.0.1", port)

    # 1. 404 Not Found from upstream
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps({"method": "GET", "path": "/agents/nonexistent-id-999"}).encode("utf-8"),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
        },
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode("utf-8"))
    assert res.status == 200
    assert body["status"] == 404
    assert body["ok"] is False

    # 2. Upstream 429 Rate Limit
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps({"method": "GET", "path": "/agents/rate-limit-429"}).encode("utf-8"),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
        },
    )
    res2 = conn.getresponse()
    body2 = json.loads(res2.read().decode("utf-8"))
    assert res2.status == 200
    assert body2["status"] == 429
    assert body2["ok"] is False
    assert "Rate limit" in body2["data"]["error"]

    # 3. Upstream 500 Server Error (returns 502 Bad Gateway to client)
    conn.request(
        "POST",
        "/api/run",
        body=json.dumps({"method": "GET", "path": "/agents/server-error-500"}).encode("utf-8"),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
        },
    )
    res3 = conn.getresponse()
    body3 = json.loads(res3.read().decode("utf-8"))
    conn.close()
    assert res3.status == 502
    assert body3["status"] == 500
    assert body3["ok"] is False


def test_proxy_execution_logs_to_request_history(integration_app):
    host_port, port = integration_app
    conn = http.client.HTTPConnection("127.0.0.1", port)

    conn.request(
        "POST",
        "/api/run",
        body=json.dumps({"method": "GET", "path": "/phone_number/list"}).encode("utf-8"),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
        },
    )
    res = conn.getresponse()
    assert res.status == 200
    conn.close()

    # Query history to verify it was recorded
    history = omnidim_ui.get_history(limit=5)
    items = history["items"]
    assert any(h["path"] == "/phone_number/list" for h in items)
