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
        url="https://omnidim.io/api/v1/agents",
        transport=mock.Mock(side_effect=TimeoutError()),
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
            body=json.dumps({"baseUrl": "https://omnidim.io/api/v1", "retentionLimit": 2500}).encode(),
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
        assert body_set_post["baseUrl"] == "https://omnidim.io/api/v1"
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
        omnidim_ui.dpapi_unprotect("dpapi:!not-base64!", crypt32=mock.MagicMock(), kernel32=mock.MagicMock())

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


def test_security_high_coverage_branches(tmp_path):
    import base64
    import time

    from omnidim_ui.security import (
        consume_confirm_token,
        dpapi_protect,
        dpapi_unprotect,
        is_valid_csrf,
        is_valid_host,
        is_valid_origin,
        issue_confirm_token,
        migrate_legacy_enc_v1,
        purge_expired_confirmation_tokens,
        redact_payload,
        sanitize_url,
        save_api_key,
        secure_db_file,
    )

    # 1. Host and Origin edge cases
    assert is_valid_host("") is False
    assert is_valid_host("evil.example.com") is False
    assert is_valid_origin("") is True
    assert is_valid_origin("ftp://localhost") is False
    assert is_valid_origin("not-a-valid-origin") is False
    assert is_valid_csrf("") is False
    with mock.patch("urllib.parse.urlparse", side_effect=ValueError("bad")):
        assert is_valid_origin("http://localhost") is False

    # 2. redact_payload and sanitize_url
    redacted = redact_payload({"api_key": "secret", "file": "a" * 150, "nested": {"password": "pass"}})
    assert redacted["api_key"] == "[REDACTED]"
    assert "BASE64_FILE" in redacted["file"]
    assert redacted["nested"]["password"] == "[REDACTED]"

    clean_url = sanitize_url("https://api.omnidim.io/v1/agents?api_key=secret&limit=10")
    assert "api_key=%5BREDACTED%5D" in clean_url or "api_key=[REDACTED]" in clean_url
    assert "limit=10" in clean_url
    assert sanitize_url("https://api.omnidim.io/v1/agents") == "https://api.omnidim.io/v1/agents"
    with mock.patch("urllib.parse.urlparse", side_effect=ValueError("bad")):
        assert sanitize_url("https://bad.url") == "[INVALID URL REDACTED]"

    # 3. Empty api key save
    assert save_api_key("") == "none"

    # 4. Confirmation tokens: purge, session mismatch, signature mismatch, endpoint mismatch, expired
    issue_confirm_token("ep1", "sig-123", session_id="sess-abc")
    purged = purge_expired_confirmation_tokens(now=time.time() + 100)
    assert purged >= 1

    tok2 = issue_confirm_token("ep1", "sig-123", session_id="sess-abc")
    ok, reason = consume_confirm_token(tok2, "ep1", "sig-123", session_id="sess-mismatch")
    assert ok is False
    assert "different local session" in reason

    tok3 = issue_confirm_token("ep1", "sig-123", session_id="sess-abc")
    ok, reason = consume_confirm_token(tok3, "ep1", "sig-tampered", session_id="sess-abc")
    assert ok is False
    assert "modified after confirmation token" in reason

    tok4 = issue_confirm_token("ep1", "sig-123", session_id="sess-abc")
    ok, reason = consume_confirm_token(tok4, "ep-different", "sig-123", session_id="sess-abc")
    assert ok is False
    assert "different endpoint" in reason

    tok_expired = issue_confirm_token("ep1", "sig-123", session_id="sess-abc")
    with mock.patch("time.time", return_value=time.time() + 100):
        ok, reason = consume_confirm_token(tok_expired, "ep1", "sig-123", session_id="sess-abc")
        assert ok is False
        assert "Invalid, expired, or already-used" in reason

    # 5. Keyring exception handling
    mock_kr_fail = mock.MagicMock()
    mock_kr_fail.get_password.side_effect = Exception("keyring locked")
    mock_kr_fail.set_password.side_effect = Exception("keyring disk full")
    with mock.patch.object(omnidim_ui.security, "keyring", mock_kr_fail):
        with mock.patch.object(omnidim_ui.security, "IS_WINDOWS", False):
            with mock.patch.dict("os.environ", {}, clear=True):
                k, s = omnidim_ui.get_api_key()
                assert k == ""
                assert s == "none"

            with pytest.raises(ValueError, match="Failed to store API key in OS keyring"):
                save_api_key("key-fail")

    # 6. DPAPI non-Windows NotImplementedError branches
    with mock.patch.object(omnidim_ui.security, "IS_WINDOWS", False):
        with pytest.raises(NotImplementedError, match="Windows DPAPI is only available on Windows"):
            dpapi_protect("secret", crypt32=None, kernel32=None)
        with pytest.raises(NotImplementedError, match="Windows DPAPI is only available on Windows"):
            dpapi_unprotect("dpapi:dGVzdA==", crypt32=None, kernel32=None)

    # 7. DPAPI CryptProtectData & CryptUnprotectData mock failure branches
    mock_crypt = mock.MagicMock()
    mock_crypt.CryptProtectData.return_value = 0
    mock_crypt.CryptUnprotectData.return_value = 0
    mock_kernel = mock.MagicMock()
    with pytest.raises(RuntimeError, match="Windows DPAPI CryptProtectData failed"):
        dpapi_protect("secret", crypt32=mock_crypt, kernel32=mock_kernel)

    valid_dpapi_str = "dpapi:" + base64.b64encode(b"dummy").decode()
    with pytest.raises(RuntimeError, match="Windows DPAPI CryptUnprotectData failed"):
        dpapi_unprotect(valid_dpapi_str, crypt32=mock_crypt, kernel32=mock_kernel)

    # 8. secure_db_file exception handling
    test_file = tmp_path / "test.db"
    test_file.touch()
    with mock.patch("os.chmod", side_effect=OSError("permission denied")):
        secure_db_file(test_file)

    # 9. DPAPI decryption failure in get_api_key
    test_db = tmp_path / "test_dpapi_fail.sqlite3"
    omnidim_ui.init_db(test_db)
    with omnidim_ui.get_db(test_db) as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('api_key', 'dpapi:bad', '2026-01-01')")
    with mock.patch.object(omnidim_ui.security, "dpapi_unprotect", side_effect=RuntimeError("corrupted DPAPI")):
        with mock.patch.dict("os.environ", {}, clear=True):
            with omnidim_ui.get_db(test_db) as conn:
                key_res, src_res = omnidim_ui.get_api_key(db_conn=conn)
                assert key_res == ""
                assert src_res == "none"

    # 10. migrate_legacy_enc_v1 on non-Windows with keyring
    sec_dir = tmp_path / "data_mig"
    sec_dir.mkdir(parents=True)
    secret_key = b"A" * 32
    (sec_dir / ".secret_key").write_bytes(secret_key)
    # encrypt with legacy scheme
    import hashlib
    import hmac
    nonce = b"1234567890123456"
    plaintext = b"legacy-secret-key-123"
    k_enc = hmac.new(secret_key, b"ENC:" + nonce, hashlib.sha256).digest()
    k_mac = hmac.new(secret_key, b"MAC:" + nonce, hashlib.sha256).digest()
    blocks = (len(plaintext) + 31) // 32
    keystream = b"".join(hmac.new(k_enc, i.to_bytes(4, "big"), hashlib.sha256).digest() for i in range(blocks))
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream[:len(plaintext)], strict=True))
    tag = hmac.new(k_mac, nonce + ciphertext, hashlib.sha256).hexdigest()
    enc_v1_str = f"enc:v1:{nonce.hex()}:{ciphertext.hex()}:{tag}"

    mig_db = tmp_path / "mig.sqlite3"
    omnidim_ui.init_db(mig_db)
    with omnidim_ui.get_db(mig_db) as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('api_key', ?, '2026-01-01')", (enc_v1_str,))

    mock_kr = mock.MagicMock()
    with mock.patch.object(omnidim_ui.config, "DATA_DIR", sec_dir):
        with mock.patch.object(omnidim_ui.security, "IS_WINDOWS", False):
            with mock.patch.object(omnidim_ui.security, "keyring", mock_kr):
                with omnidim_ui.get_db(mig_db) as conn:
                    migrate_legacy_enc_v1(db_conn=conn)
                    mock_kr.set_password.assert_called_with("omnidim_control_center", "api_key", "legacy-secret-key-123")
                    # Key deleted from settings table
                    row = conn.execute("SELECT value FROM settings WHERE key = 'api_key'").fetchone()
                    assert row is None
                    assert not (sec_dir / ".secret_key").exists()
