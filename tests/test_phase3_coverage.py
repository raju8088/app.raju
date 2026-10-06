"""Comprehensive test suite ensuring >85% branch and statement coverage for omnidim_ui."""

from __future__ import annotations

import http.client
import json
import logging
import threading
from unittest import mock

import pytest

import omnidim_ui
from omnidim_ui import config
from omnidim_ui.__main__ import main
from omnidim_ui.drift_check import check_catalog_drift, format_drift_report
from omnidim_ui.logging_config import setup_logging
from omnidim_ui.proxy import build_url, decode_response, execute_proxy_request


def test_main_cli_entrypoint(tmp_path):
    orig_ro = config.READ_ONLY_MODE
    orig_db = config.DB_PATH
    try:
        with mock.patch("omnidim_ui.__main__.ThreadingHTTPServer") as mock_server_cls:
            mock_server = mock.MagicMock()
            mock_server_cls.return_value = mock_server
            custom_db = tmp_path / "custom.sqlite3"
            ret = main(["--host", "127.0.0.1", "--port", "9999", "--db", str(custom_db), "--read-only", "--verbose"])
            assert ret == 0
            assert config.READ_ONLY_MODE is True
            assert config.DB_PATH == custom_db.resolve()
            mock_server_cls.assert_called_once_with(("127.0.0.1", 9999), omnidim_ui.handlers.AppHandler)
            mock_server.serve_forever.assert_called_once()
            mock_server.server_close.assert_called_once()

            # Test KeyboardInterrupt branch
            mock_server.serve_forever.side_effect = KeyboardInterrupt
            ret_ki = main([])
            assert ret_ki == 0
    finally:
        config.READ_ONLY_MODE = orig_ro
        config.DB_PATH = orig_db


def test_logging_configuration():
    setup_logging(verbose=True)
    assert logging.getLogger("omnidim_ui").level == logging.DEBUG
    setup_logging(verbose=False)
    assert logging.getLogger("omnidim_ui").level == logging.INFO


def test_drift_check_formatting_and_errors(tmp_path):
    report = check_catalog_drift()
    text = format_drift_report(report)
    assert "OmniDimension OpenAPI Drift Report" in text
    assert "Coverage:" in text

    # Test report formatting with unlisted/unimplemented items
    dummy_report = {
        "totalSpecOperations": 10,
        "totalCatalogOperations": 10,
        "coveredOperations": 8,
        "coveragePercentage": 80.0,
        "unimplementedInCatalog": [("POST", "/unimplemented")],
        "unlistedInOpenAPI": [("GET", "/unlisted")],
    }
    dummy_text = format_drift_report(dummy_report)
    assert "/unimplemented" in dummy_text
    assert "/unlisted" in dummy_text

    # Test missing spec file error
    with pytest.raises(FileNotFoundError):
        check_catalog_drift(tmp_path / "nonexistent.yaml")


def test_proxy_helpers():
    # decode_response edge cases
    assert decode_response(None, None) is None
    assert decode_response(b"", "utf-8") is None
    assert decode_response(b"not-json-plain-text", "utf-8") == "not-json-plain-text"

    # build_url query formatting
    url = build_url(
        "https://api.omnidim.io/v1/",
        "/test",
        {"tags": ["voice", "agent"], "empty": None, "blank": "", "single": "1"},
    )
    assert "https://api.omnidim.io/v1/test?" in url
    assert "tags=voice" in url
    assert "tags=agent" in url
    assert "single=1" in url
    assert "empty=" not in url
    assert "blank=" not in url

    # Proxy network failure
    status, ok, data = execute_proxy_request(
        method="GET",
        url="http://invalid-nonexistent-domain-9999.local/test",
        api_key="key",
        timeout=1,
        max_retries=1,
    )
    assert status is None
    assert ok is False
    assert "error" in data


def test_handlers_static_and_health_endpoints(tmp_path):
    from http.server import ThreadingHTTPServer

    orig_db = config.DB_PATH
    config.DB_PATH = tmp_path / "handler_test.sqlite3"
    try:
        omnidim_ui.init_db()
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), omnidim_ui.AppHandler)
        host, port = httpd.server_address
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()

        conn = http.client.HTTPConnection("127.0.0.1", port)

        # 1. GET /api/health
        conn.request("GET", "/api/health", headers={"Host": f"127.0.0.1:{port}", "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN})
        res = conn.getresponse()
        body = json.loads(res.read().decode())
        assert res.status == 200
        assert body["ok"] is True
        assert body["endpointCount"] > 0

        # 2. Static files
        conn.request("GET", "/app.js", headers={"Host": f"127.0.0.1:{port}"})
        res_js = conn.getresponse()
        assert res_js.status == 200
        assert "javascript" in res_js.getheader("content-type", "")
        res_js.read()

        conn.request("GET", "/styles.css", headers={"Host": f"127.0.0.1:{port}"})
        res_css = conn.getresponse()
        assert res_css.status == 200
        assert "css" in res_css.getheader("content-type", "")
        res_css.read()

        conn.request("GET", "/static/nonexistent-file.xyz", headers={"Host": f"127.0.0.1:{port}"})
        res_404 = conn.getresponse()
        assert res_404.status == 404
        res_404.read()

        # 3. GET /api/session
        conn.request("GET", "/api/session", headers={"Host": f"127.0.0.1:{port}", "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN})
        res_sess = conn.getresponse()
        body_sess = json.loads(res_sess.read().decode())
        assert res_sess.status == 200
        assert body_sess["csrfToken"] == omnidim_ui.CSRF_TOKEN

        # 4. GET /api/endpoints
        conn.request("GET", "/api/endpoints", headers={"Host": f"127.0.0.1:{port}", "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN})
        res_ep = conn.getresponse()
        body_ep = json.loads(res_ep.read().decode())
        assert res_ep.status == 200
        assert len(body_ep["endpoints"]) > 0

        # 5. GET /api/settings and POST /api/settings
        conn.request("GET", "/api/settings", headers={"Host": f"127.0.0.1:{port}", "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN})
        res_set = conn.getresponse()
        assert res_set.status == 200
        res_set.read()

        conn.request(
            "POST",
            "/api/settings",
            body=json.dumps({"baseUrl": "https://api.custom.com/v1", "retentionLimit": 2500}).encode(),
            headers={
                "Host": f"127.0.0.1:{port}",
                "Content-Type": "application/json",
                "Origin": f"http://127.0.0.1:{port}",
                "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
                "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
            },
        )
        res_set_post = conn.getresponse()
        body_set_post = json.loads(res_set_post.read().decode())
        assert res_set_post.status == 200
        assert body_set_post["baseUrl"] == "https://api.custom.com/v1"
        assert body_set_post["retentionLimit"] == 2500

        # 6. DELETE /api/settings/api-key
        conn.request(
            "DELETE",
            "/api/settings/api-key",
            headers={
                "Host": f"127.0.0.1:{port}",
                "Origin": f"http://127.0.0.1:{port}",
                "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
                "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
            },
        )
        res_del_key = conn.getresponse()
        body_del_key = json.loads(res_del_key.read().decode())
        assert res_del_key.status == 200
        assert body_del_key["hasApiKey"] is False

        # Saved-payloads CRUD
        conn.request(
            "POST",
            "/api/saved-payloads",
            body=json.dumps({"endpoint_id": "ep1", "name": "test payload", "method": "GET", "path": "/agents"}).encode(),
            headers={
                "Host": f"127.0.0.1:{port}",
                "Content-Type": "application/json",
                "Origin": f"http://127.0.0.1:{port}",
                "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
                "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
            },
        )
        res_sp = conn.getresponse()
        assert res_sp.status == 200
        sp_id = json.loads(res_sp.read().decode())["id"]

        conn.request("GET", "/api/saved-payloads", headers={"Host": f"127.0.0.1:{port}", "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN})
        res_get_sp = conn.getresponse()
        assert res_get_sp.status == 200
        assert len(json.loads(res_get_sp.read().decode())["records"]) >= 1

        conn.request(
            "DELETE",
            f"/api/saved-payloads/{sp_id}",
            headers={
                "Host": f"127.0.0.1:{port}",
                "Origin": f"http://127.0.0.1:{port}",
                "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
                "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
            },
        )
        res_del_sp = conn.getresponse()
        assert res_del_sp.status == 200
        res_del_sp.read()

        # History clear
        conn.request(
            "POST",
            "/api/history/clear",
            body=b"{}",
            headers={
                "Host": f"127.0.0.1:{port}",
                "Content-Type": "application/json",
                "Origin": f"http://127.0.0.1:{port}",
                "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
                "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
            },
        )
        res_hist_clear = conn.getresponse()
        assert res_hist_clear.status == 200
        res_hist_clear.read()

        # 7. Security header rejection checks
        # Bad Host
        conn.request("GET", "/api/health", headers={"Host": "attacker.com", "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN})
        res_bad_host = conn.getresponse()
        assert res_bad_host.status == 403
        res_bad_host.read()

        # Bad Origin
        conn.request(
            "POST",
            "/api/settings",
            body=json.dumps({"baseUrl": "https://attacker.com"}).encode(),
            headers={
                "Host": f"127.0.0.1:{port}",
                "Origin": "http://evil.com",
                "Content-Type": "application/json",
                "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
                "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
            },
        )
        res_bad_origin = conn.getresponse()
        assert res_bad_origin.status == 403
        res_bad_origin.read()

        # Bad CSRF
        conn.request(
            "POST",
            "/api/settings",
            body=json.dumps({"baseUrl": "https://api.test.com"}).encode(),
            headers={
                "Host": f"127.0.0.1:{port}",
                "Origin": f"http://127.0.0.1:{port}",
                "Content-Type": "application/json",
                "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
                "X-CSRF-Token": "bad-csrf-token",
            },
        )
        res_bad_csrf = conn.getresponse()
        assert res_bad_csrf.status == 403
        res_bad_csrf.read()

        # Missing auth
        conn.request("GET", "/api/health", headers={"Host": f"127.0.0.1:{port}"})
        res_no_auth = conn.getresponse()
        assert res_no_auth.status == 401
        res_no_auth.read()

        # Cookie auth supported
        conn.request(
            "GET",
            "/api/health",
            headers={"Host": f"127.0.0.1:{port}", "Cookie": f"local_token={omnidim_ui.LOCAL_AUTH_TOKEN}"},
        )
        res_cookie = conn.getresponse()
        assert res_cookie.status == 200
        res_cookie.read()

        # Read-only rejection test
        orig_ro = config.READ_ONLY_MODE
        try:
            config.READ_ONLY_MODE = True
            conn.request(
                "POST",
                "/api/settings",
                body=json.dumps({"baseUrl": "https://api.test.com"}).encode(),
                headers={
                    "Host": f"127.0.0.1:{port}",
                    "Origin": f"http://127.0.0.1:{port}",
                    "Content-Type": "application/json",
                    "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
                    "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
                },
            )
            res_ro = conn.getresponse()
            assert res_ro.status == 403
            res_ro.read()
        finally:
            config.READ_ONLY_MODE = orig_ro

        # Unknown API endpoint -> 404
        conn.request(
            "GET",
            "/api/unknown-endpoint-xyz",
            headers={"Host": f"127.0.0.1:{port}", "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN},
        )
        res_api_404 = conn.getresponse()
        assert res_api_404.status == 404
        res_api_404.read()

        # Invalid JSON body on mutating request
        conn.request(
            "POST",
            "/api/settings",
            body=b"{invalid-json",
            headers={
                "Host": f"127.0.0.1:{port}",
                "Content-Type": "application/json",
                "Origin": f"http://127.0.0.1:{port}",
                "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
                "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
            },
        )
        res_bad_json = conn.getresponse()
        assert res_bad_json.status == 400
        res_bad_json.read()

        # Unsupported method on /api/run
        conn.request(
            "POST",
            "/api/run",
            body=json.dumps({"method": "HEAD", "path": "/agents"}).encode(),
            headers={
                "Host": f"127.0.0.1:{port}",
                "Content-Type": "application/json",
                "X-Local-Token": omnidim_ui.LOCAL_AUTH_TOKEN,
                "X-CSRF-Token": omnidim_ui.CSRF_TOKEN,
            },
        )
        res_unsupported = conn.getresponse()
        assert res_unsupported.status == 400
        res_unsupported.read()

        conn.close()
        httpd.shutdown()
        httpd.server_close()
    finally:
        config.DB_PATH = orig_db


def test_security_dpapi_and_keyring_edge_cases(tmp_path):
    # Test invalid DPAPI strings
    with pytest.raises(ValueError, match="Not a valid DPAPI payload"):
        omnidim_ui.dpapi_unprotect("not-dpapi-prefix")

    with pytest.raises(ValueError, match="Invalid DPAPI base64 payload"):
        omnidim_ui.dpapi_unprotect("dpapi:!not-base64!")

    # Test secure_db_file with non-existent path
    omnidim_ui.security.secure_db_file(tmp_path / "does_not_exist.sqlite3")

    # Test keyring mock save and retrieve
    mock_kr = mock.MagicMock()
    mock_kr.get_password.return_value = "kr-secret-123"
    with mock.patch.object(omnidim_ui.security, "keyring", mock_kr):
        with mock.patch.object(omnidim_ui.security, "IS_WINDOWS", False):
            # Save
            src = omnidim_ui.save_api_key("kr-secret-123")
            assert src == "keyring"
            mock_kr.set_password.assert_called_with("omnidim_control_center", "api_key", "kr-secret-123")

            # Get
            with mock.patch.dict("os.environ", {}, clear=True):
                k, s = omnidim_ui.get_api_key()
                assert k == "kr-secret-123"
                assert s == "keyring"

            # Delete
            omnidim_ui.delete_api_key()
            mock_kr.delete_password.assert_called_with("omnidim_control_center", "api_key")

    # Test refuse to store when no keyring and not Windows
    with mock.patch.object(omnidim_ui.security, "keyring", None):
        with mock.patch.object(omnidim_ui.security, "IS_WINDOWS", False):
            with pytest.raises(ValueError, match="Secure OS key storage is unavailable"):
                omnidim_ui.save_api_key("refused-key")
