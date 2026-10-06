import http.client
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import omnidim_ui
from omnidim_ui import db, proxy
from omnidim_ui.drift_check import check_catalog_drift


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


def test_schema_version_and_wal_mode(tmp_path):
    test_db = tmp_path / "test_migration.sqlite3"
    db.init_db(test_db)

    with db.get_db(test_db) as conn:
        # 1. Verify WAL journal mode
        journal_row = conn.execute("PRAGMA journal_mode").fetchone()
        assert journal_row[0].lower() == "wal"

        # 2. Verify schema_version table
        rows = conn.execute("SELECT version, description FROM schema_version ORDER BY version ASC").fetchall()
        versions = [r["version"] for r in rows]
        assert 1 in versions
        assert 2 in versions

        # 3. Verify indexes from migration 2 exist
        idx_rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'").fetchall()
        index_names = {r["name"] for r in idx_rows}
        assert "idx_history_created_at" in index_names
        assert "idx_history_endpoint_id" in index_names
        assert "idx_history_status" in index_names
        assert "idx_history_method" in index_names


def test_history_pagination_and_filtering(tmp_path):
    test_db = tmp_path / "test_history.sqlite3"
    db.init_db(test_db)

    # Insert 15 synthetic history items
    with db.get_db(test_db) as conn:
        for i in range(15):
            status = 200 if i % 2 == 0 else 500
            method = "GET" if i < 10 else "POST"
            path = f"/agents/{i}" if i < 8 else f"/calls/dispatch/{i}"
            db.log_history(
                endpoint_id_value=f"ep-{i}",
                method=method,
                path=path,
                url=f"https://api.omnidim.io/v1{path}",
                status=status,
                ok=(status == 200),
                duration_ms=10 + i,
                request_payload={"idx": i},
                response_payload={"result": "ok" if status == 200 else "err"},
                db_conn=conn,
            )

    # 1. Test pagination page 1, limit 5
    page1 = db.get_history(page=1, limit=5, db_conn=test_db)
    assert page1["total"] == 15
    assert len(page1["items"]) == 5
    assert page1["totalPages"] == 3
    assert page1["page"] == 1

    # 2. Test pagination page 2, limit 5
    page2 = db.get_history(page=2, limit=5, db_conn=test_db)
    assert len(page2["items"]) == 5
    assert page2["items"][0]["id"] != page1["items"][0]["id"]

    # 3. Test search filter (matches 'agents')
    agent_results = db.get_history(search="agents", db_conn=test_db)
    assert agent_results["total"] == 8
    for item in agent_results["items"]:
        assert "agents" in item["path"]

    # 4. Test status filter (matches status 500)
    status_500 = db.get_history(status=500, db_conn=test_db)
    assert all(item["status"] == 500 for item in status_500["items"])
    assert status_500["total"] == 7

    # 5. Test method filter (matches method 'POST')
    post_results = db.get_history(method="POST", db_conn=test_db)
    assert post_results["total"] == 5
    assert all(item["method"] == "POST" for item in post_results["items"])


def test_history_api_endpoint_pagination(live_server):
    host_port, port = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request(
        "GET",
        "/api/history?page=1&limit=5&search=agents",
        headers={"Host": f"127.0.0.1:{port}", "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN},
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    conn.close()

    assert res.status == 200
    assert body["ok"] is True
    assert "items" in body
    assert "records" in body
    assert "total" in body
    assert "page" in body
    assert "limit" in body
    assert "totalPages" in body


class MockUpstreamHandler(BaseHTTPRequestHandler):
    get_request_count = 0
    post_request_count = 0

    def do_GET(self):
        MockUpstreamHandler.get_request_count += 1
        # Fail the first 2 attempts, succeed on the 3rd attempt
        if MockUpstreamHandler.get_request_count < 3:
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Temporary server error"}')
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok", "recovered": true}')

    def do_POST(self):
        MockUpstreamHandler.post_request_count += 1
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > 0:
            self.rfile.read(length)
        self.send_response(500)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"error": "Internal server error"}')

    def log_message(self, fmt, *args):
        pass  # Suppress mock logs during tests


@pytest.fixture(scope="module")
def mock_upstream():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), MockUpstreamHandler)
    host, port = httpd.server_address
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://{host}:{port}"
    httpd.shutdown()
    httpd.server_close()


def test_proxy_idempotent_get_retries_and_recovers(mock_upstream):
    MockUpstreamHandler.get_request_count = 0
    url = f"{mock_upstream}/test/idempotent"

    status, ok, data = proxy.execute_proxy_request(
        method="GET",
        url=url,
        api_key="test-key",
        timeout=5,
        max_retries=3,
        backoff_factor=0.05,  # Fast backoff for testing
    )

    # Should have retried and succeeded on 3rd attempt
    assert MockUpstreamHandler.get_request_count == 3
    assert status == 200
    assert ok is True
    assert data["recovered"] is True


def test_proxy_mutating_post_never_retries(mock_upstream):
    MockUpstreamHandler.post_request_count = 0
    url = f"{mock_upstream}/test/mutating"

    status, ok, data = proxy.execute_proxy_request(
        method="POST",
        url=url,
        api_key="test-key",
        body={"name": "test"},
        timeout=5,
        max_retries=3,
        backoff_factor=0.05,
    )

    # Mutating POST must NEVER be retried; count must strictly be 1
    assert MockUpstreamHandler.post_request_count == 1
    assert status == 500
    assert ok is False


def test_openapi_catalog_drift_100_percent():
    report = check_catalog_drift()
    assert report["coveragePercentage"] == 100.0
    assert report["totalSpecOperations"] == 72
    assert report["totalCatalogOperations"] == 72
    assert len(report["unlistedInOpenAPI"]) == 0
    assert len(report["unimplementedInCatalog"]) == 0


def test_history_retention_setting_and_clear_api(live_server):
    host_port, port = live_server
    omnidim_ui.delete_setting("history_retention_limit")
    conn = http.client.HTTPConnection("127.0.0.1", port)

    # 1. Default retention limit is 5000
    conn.request(
        "GET",
        "/api/settings",
        headers={"Host": f"127.0.0.1:{port}", "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN},
    )
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    assert body["retentionLimit"] == 5000

    # 2. Update retention limit via /api/settings
    conn.request(
        "POST",
        "/api/settings",
        body=json.dumps({"retentionLimit": 25}).encode(),
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
    assert res.status == 200
    assert body["retentionLimit"] == 25

    # 3. Insert 30 items directly, then log_history should prune to 25
    with omnidim_ui.get_db() as db_conn:
        db_conn.execute("DELETE FROM request_history")
        for i in range(30):
            db_conn.execute(
                """
                INSERT INTO request_history
                (endpoint_id, method, path, url, status, ok, duration_ms, request_json, response_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (f"ep-{i}", "GET", f"/path/{i}", "https://api.omnidim.io/v1", 200, 1, 10, "{}", "{}", "2026-01-01T00:00:00Z"),
            )

    omnidim_ui.log_history("ep-new", "GET", "/new", "https://api.omnidim.io/v1/new", 200, True, 5, {}, {})
    with omnidim_ui.get_db() as db_conn:
        count = db_conn.execute("SELECT COUNT(*) FROM request_history").fetchone()[0]
        assert count == 25

    # 4. Rejection of invalid limits (< 10 or > 50,000)
    conn.request(
        "POST",
        "/api/settings",
        body=json.dumps({"retentionLimit": 5}).encode(),
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "Origin": f"http://127.0.0.1:{port}",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
        },
    )
    res = conn.getresponse()
    err_body = json.loads(res.read().decode())
    assert res.status == 400
    assert "between 10 and 50,000" in err_body["error"]

    # 5. Clear history via DELETE /api/history
    conn.request(
        "DELETE",
        "/api/history",
        headers={
            "Host": f"127.0.0.1:{port}",
            "Origin": f"http://127.0.0.1:{port}",
            "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
            "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
        },
    )
    res = conn.getresponse()
    clear_body = json.loads(res.read().decode())
    assert res.status == 200
    assert clear_body["ok"] is True

    with omnidim_ui.get_db() as db_conn:
        remaining = db_conn.execute("SELECT COUNT(*) FROM request_history").fetchone()[0]
        assert remaining == 0

    # 6. Reset retention limit back to default
    omnidim_ui.delete_setting("history_retention_limit")
    conn.close()

