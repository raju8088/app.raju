import os
from unittest import mock

import omnidim_ui


def test_api_key_env_var_priority():
    # 1. When env var is present
    with mock.patch.dict(os.environ, {"OMNIDIM_API_KEY": "env-test-key-123456"}):
        key, source = omnidim_ui.get_api_key()
        assert key == "env-test-key-123456"
        assert source == "env"

        settings = omnidim_ui.read_settings(include_secret=True)
        assert settings["apiKey"] == "env-test-key-123456"
        assert settings["apiKeySource"] == "env"
        assert "environment variable" in settings["securityNotice"]


def test_redact_payload_recursive():
    payload = {
        "Name": "John",
        "api_key": "secret-123",
        "nested": {
            "AUTH_TOKEN": "token-xyz",
            "sip_password": "super-sip-secret",
            "account_sid": "AC1234567890",
            "normal_field": 42,
        },
        "list_items": [
            {"user": "Alice", "password": "alice-password"},
            {"user": "Bob", "token": "bearer-bob"},
        ],
    }
    redacted = omnidim_ui.redact_payload(payload)

    assert redacted["Name"] == "John"
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["nested"]["AUTH_TOKEN"] == "[REDACTED]"
    assert redacted["nested"]["sip_password"] == "[REDACTED]"
    assert redacted["nested"]["account_sid"] == "[REDACTED]"
    assert redacted["nested"]["normal_field"] == 42
    assert redacted["list_items"][0]["password"] == "[REDACTED]"
    assert redacted["list_items"][1]["token"] == "[REDACTED]"


def test_redact_large_base64_file():
    payload = {
        "filename": "document.pdf",
        "file": "JVBERi0xLjQKJcTl8uXr...very-long-base64-string-over-100-characters" * 10,
    }
    redacted = omnidim_ui.redact_payload(payload)
    assert redacted["filename"] == "document.pdf"
    assert "BASE64_FILE:" in redacted["file"]
    assert "redacted" in redacted["file"]


def test_sanitize_url_removes_secrets():
    raw_url = "https://omnidim.io/api/v1/resource?normal=1&api_key=secret-val&token=abc"
    clean = omnidim_ui.sanitize_url(raw_url)
    assert "normal=1" in clean
    assert "secret-val" not in clean
    assert "abc" not in clean
    assert "api_key=%5BREDACTED%5D" in clean or "api_key=[REDACTED]" in clean


def test_history_logging_redaction_and_retention():
    omnidim_ui.init_db()
    with omnidim_ui.get_db() as conn:
        conn.execute("DELETE FROM request_history")

    # Log an entry with sensitive payload
    sensitive_req = {"api_key": "my-secret-key", "action": "test"}
    sensitive_res = {"token": "returned-token", "ok": True}
    sensitive_url = "https://omnidim.io/api/v1/test?token=query-secret"

    omnidim_ui.log_history(
        "test-ep",
        "POST",
        "/test",
        sensitive_url,
        200,
        True,
        15,
        sensitive_req,
        sensitive_res,
    )

    with omnidim_ui.get_db() as conn:
        row = conn.execute("SELECT * FROM request_history ORDER BY id DESC LIMIT 1").fetchone()
        assert row is not None
        assert "my-secret-key" not in row["request_json"]
        assert "[REDACTED]" in row["request_json"]
        assert "returned-token" not in row["response_json"]
        assert "[REDACTED]" in row["response_json"]
        assert "query-secret" not in row["url"]


def test_history_auto_prune_limit():
    omnidim_ui.init_db()
    with omnidim_ui.get_db() as conn:
        conn.execute("DELETE FROM request_history")
        # Insert 505 rows directly
        conn.executemany(
            """
            INSERT INTO request_history
            (endpoint_id, method, path, url, status, ok, duration_ms, request_json, response_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [("ep", "GET", "/", "/", 200, 1, 1, "{}", "{}", "2026-01-01T00:00:00Z") for _ in range(505)],
        )

    # Calling log_history should prune to retention limit (500)
    omnidim_ui.log_history("ep", "GET", "/", "/", 200, True, 1, {}, {})

    with omnidim_ui.get_db() as conn:
        count = conn.execute("SELECT COUNT(*) FROM request_history").fetchone()[0]
        assert count == omnidim_ui.HISTORY_RETENTION_LIMIT


def test_dpapi_protect_and_unprotect_with_mocks():
    import ctypes

    from omnidim_ui.security import dpapi_protect, dpapi_unprotect, setup_dpapi_signatures

    mock_crypt32 = mock.MagicMock()
    mock_kernel32 = mock.MagicMock()

    # Verify signature configuration
    setup_dpapi_signatures(mock_crypt32, mock_kernel32)
    assert len(mock_crypt32.CryptProtectData.argtypes) == 7
    assert mock_crypt32.CryptProtectData.restype == ctypes.c_int
    assert len(mock_crypt32.CryptUnprotectData.argtypes) == 7
    assert mock_crypt32.CryptUnprotectData.restype == ctypes.c_int
    assert mock_kernel32.LocalFree.argtypes == [ctypes.c_void_p]
    assert mock_kernel32.LocalFree.restype == ctypes.c_void_p

    # Test Protect Data with mock
    fake_cipher_bytes = b"encrypted-blob-sample"
    allocated_buf = ctypes.create_string_buffer(fake_cipher_bytes)

    def fake_protect(pDataIn, szDataDescr, pEntropy, pReserved, pPrompt, dwFlags, pDataOut):
        out_blob = pDataOut._obj
        out_blob.cbData = len(fake_cipher_bytes)
        out_blob.pbData = ctypes.cast(allocated_buf, ctypes.POINTER(ctypes.c_byte))
        return 1

    mock_crypt32.CryptProtectData.side_effect = fake_protect
    res = dpapi_protect("test-secret", crypt32=mock_crypt32, kernel32=mock_kernel32)

    assert res.startswith("dpapi:")
    # Verify LocalFree called in finally block
    mock_kernel32.LocalFree.assert_called_once()

    # Test Unprotect Data with mock
    mock_kernel32.reset_mock()
    plain_bytes = b"test-secret"
    plain_buf = ctypes.create_string_buffer(plain_bytes)

    def fake_unprotect(pDataIn, ppszDescr, pEntropy, pReserved, pPrompt, dwFlags, pDataOut):
        out_blob = pDataOut._obj
        out_blob.cbData = len(plain_bytes)
        out_blob.pbData = ctypes.cast(plain_buf, ctypes.POINTER(ctypes.c_byte))
        return 1

    mock_crypt32.CryptUnprotectData.side_effect = fake_unprotect
    decrypted = dpapi_unprotect(res, crypt32=mock_crypt32, kernel32=mock_kernel32)

    assert decrypted == "test-secret"
    # Verify LocalFree called in finally block
    mock_kernel32.LocalFree.assert_called_once()

    # Test failure handling
    mock_crypt32.CryptProtectData.side_effect = None
    mock_crypt32.CryptProtectData.return_value = 0
    import pytest
    with pytest.raises(RuntimeError, match="CryptProtectData failed"):
        dpapi_protect("secret", crypt32=mock_crypt32, kernel32=mock_kernel32)

