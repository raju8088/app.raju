import base64
import ctypes
import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import time
import urllib.parse

from omnidim_ui.config import (
    CONFIRMATION_TOKEN_TTL,
    DB_PATH,
    REDACT_KEYS,
)
from omnidim_ui.logging_config import logger

try:
    import keyring
except ImportError:
    keyring = None

IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    import ctypes.wintypes

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    def dpapi_protect(text: str) -> str:
        """Encrypt secret string using Windows DPAPI (tied to current user logon)."""
        data = text.encode("utf-8")
        in_blob = _DATA_BLOB(
            len(data),
            ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)),
        )
        out_blob = _DATA_BLOB()
        if not ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(in_blob), "OmniDimension API Key", None, None, None, 0, ctypes.byref(out_blob)
        ):
            raise RuntimeError("Windows DPAPI CryptProtectData failed")
        encrypted_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)
        return "dpapi:" + base64.b64encode(encrypted_bytes).decode("ascii")

    def dpapi_unprotect(encrypted_str: str) -> str:
        """Decrypt secret string using Windows DPAPI."""
        if not encrypted_str.startswith("dpapi:"):
            raise ValueError("Not a valid DPAPI payload")
        raw = base64.b64decode(encrypted_str[6:])
        in_blob = _DATA_BLOB(
            len(raw),
            ctypes.cast(ctypes.create_string_buffer(raw), ctypes.POINTER(ctypes.c_byte)),
        )
        out_blob = _DATA_BLOB()
        if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)
        ):
            raise RuntimeError("Windows DPAPI CryptUnprotectData failed")
        decrypted_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)
        return decrypted_bytes.decode("utf-8")

else:

    def dpapi_protect(text: str) -> str:
        raise NotImplementedError("Windows DPAPI is only available on Windows")

    def dpapi_unprotect(encrypted_str: str) -> str:
        raise NotImplementedError("Windows DPAPI is only available on Windows")


CSRF_TOKEN = secrets.token_hex(32)
LOCAL_AUTH_TOKEN = secrets.token_urlsafe(32)

CONFIRMATION_TOKENS = {}  # token -> (timestamp, endpoint_id, signature)


def is_valid_host(host_header: str) -> bool:
    if not host_header:
        return False
    host_clean = host_header.strip().lower()
    return bool(re.fullmatch(r"(127\.0\.0\.1|localhost)(:\d+)?", host_clean))


def is_valid_origin(origin_header: str) -> bool:
    if not origin_header:
        return True
    try:
        parsed = urllib.parse.urlparse(origin_header.strip().lower())
        if parsed.scheme not in {"http", "https"}:
            return False
        hostname = parsed.hostname or ""
        return hostname in {"127.0.0.1", "localhost"}
    except Exception:
        return False


def is_valid_csrf(token_header: str) -> bool:
    if not token_header:
        return False
    return hmac.compare_digest(token_header.strip(), CSRF_TOKEN)


def redact_payload(obj):
    if isinstance(obj, dict):
        redacted = {}
        for k, v in obj.items():
            k_lower = str(k).lower().strip()
            if any(target in k_lower for target in REDACT_KEYS):
                redacted[k] = "[REDACTED]"
            elif k_lower == "file" and isinstance(v, str) and len(v) > 100:
                redacted[k] = f"[BASE64_FILE: {len(v)} chars redacted]"
            else:
                redacted[k] = redact_payload(v)
        return redacted
    if isinstance(obj, list):
        return [redact_payload(item) for item in obj]
    return obj


def sanitize_url(url_str: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url_str)
        if not parsed.query:
            return url_str
        qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        sanitized_pairs = []
        for k, v in qs:
            k_lower = k.lower().strip()
            if any(target in k_lower for target in REDACT_KEYS):
                sanitized_pairs.append((k, "[REDACTED]"))
            else:
                sanitized_pairs.append((k, v))
        new_query = urllib.parse.urlencode(sanitized_pairs)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))
    except Exception:
        return url_str


def compute_danger_signature(method: str, path: str, query: dict, body: object) -> str:
    """Compute deterministic SHA-256 hash of method, path, query, and body."""
    canon_query = json.dumps(query or {}, sort_keys=True, separators=(",", ":"))
    canon_body = json.dumps(body if body is not None else {}, sort_keys=True, separators=(",", ":"))
    raw = f"{method.upper()}|{path}|{canon_query}|{canon_body}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def issue_confirm_token(endpoint_id: str, signature: str) -> str:
    """Issue a single-use 60s confirmation token cryptographically bound to the request signature."""
    now = time.time()
    expired = [k for k, (ts, _, _) in CONFIRMATION_TOKENS.items() if now - ts > CONFIRMATION_TOKEN_TTL]
    for k in expired:
        CONFIRMATION_TOKENS.pop(k, None)
    token = secrets.token_hex(16)
    CONFIRMATION_TOKENS[token] = (now, endpoint_id, signature)
    return token


def consume_confirm_token(token: str, endpoint_id: str, signature: str) -> tuple[bool, str]:
    """Validate and consume a single-use confirmation token bound to request signature."""
    now = time.time()
    if token not in CONFIRMATION_TOKENS:
        return False, "Invalid, expired, or already-used confirmation token"
    ts, ep_id, stored_sig = CONFIRMATION_TOKENS.pop(token)
    if now - ts > CONFIRMATION_TOKEN_TTL:
        return False, "Confirmation token has expired (60s lifetime exceeded)"
    if ep_id != endpoint_id:
        return False, "Confirmation token was issued for a different endpoint"
    if not hmac.compare_digest(stored_sig, signature):
        return False, "Request parameters or body were modified after confirmation token was issued"
    return True, "ok"


def secure_db_file(db_path=None):
    target = db_path or DB_PATH
    if target.exists():
        try:
            os.chmod(target, 0o600)
        except (OSError, NotImplementedError):
            pass


def get_api_key(db_conn=None):
    # 1. Environment variable has highest priority (never stored on disk)
    env_key = os.environ.get("OMNIDIM_API_KEY", "").strip()
    if env_key:
        return env_key, "env"

    # 2. Windows DPAPI (stored encrypted in SQLite settings table)
    if IS_WINDOWS:
        from omnidim_ui.db import get_db

        conn_context = None
        if db_conn is not None:
            conn = db_conn
        else:
            conn_context = get_db()
            conn = conn_context.__enter__()

        try:
            row = conn.execute("SELECT value FROM settings WHERE key = 'api_key'").fetchone()
            if row and row["value"]:
                val = str(row["value"]).strip()
                if val.startswith("dpapi:"):
                    try:
                        return dpapi_unprotect(val), "dpapi"
                    except Exception as e:
                        logger.warning("Failed to decrypt DPAPI secret: %s", e)
        finally:
            if conn_context:
                conn_context.__exit__(None, None, None)

    # 3. OS Keyring on macOS/Linux (or Windows if keyring package is present)
    if keyring:
        try:
            kr_key = keyring.get_password("omnidim_control_center", "api_key")
            if kr_key and kr_key.strip():
                return kr_key.strip(), "keyring"
        except Exception as e:
            logger.warning("Failed to fetch API key from keyring: %s", e)

    return "", "none"


def save_api_key(api_key: str, db_conn=None) -> str:
    if not api_key:
        return "none"
    from omnidim_ui.db import delete_setting, save_setting

    if IS_WINDOWS:
        encrypted = dpapi_protect(api_key)
        save_setting("api_key", encrypted, db_conn=db_conn)
        secure_db_file()
        return "dpapi"
    elif keyring:
        try:
            keyring.set_password("omnidim_control_center", "api_key", api_key)
            delete_setting("api_key", db_conn=db_conn)  # Never keep in database when using keyring
            return "keyring"
        except Exception as exc:
            raise ValueError(f"Failed to store API key in OS keyring: {exc}") from exc
    else:
        raise ValueError(
            "Secure OS key storage is unavailable on this system without the 'keyring' package. "
            "Please set the OMNIDIM_API_KEY environment variable to supply your API key securely without disk storage."
        )


def delete_api_key(db_conn=None):
    from omnidim_ui.db import delete_setting

    if keyring:
        try:
            keyring.delete_password("omnidim_control_center", "api_key")
        except Exception:
            pass
    delete_setting("api_key", db_conn=db_conn)


def migrate_legacy_enc_v1(db_conn=None):
    from omnidim_ui.config import DATA_DIR
    from omnidim_ui.db import get_db, now_iso

    secret_key_file = DATA_DIR / ".secret_key"
    conn_context = None
    if db_conn is not None:
        conn = db_conn
    else:
        conn_context = get_db()
        conn = conn_context.__enter__()

    try:
        row = conn.execute("SELECT value FROM settings WHERE key = 'api_key'").fetchone()
        if row and row["value"] and str(row["value"]).startswith("enc:v1:"):
            enc_str = str(row["value"])
            plaintext = ""
            if secret_key_file.exists():
                try:
                    secret_key = secret_key_file.read_bytes()
                    parts = enc_str.split(":")
                    if len(parts) == 5:
                        nonce = bytes.fromhex(parts[2])
                        ciphertext = bytes.fromhex(parts[3])
                        tag = parts[4]

                        k_enc = hmac.new(secret_key, b"ENC:" + nonce, hashlib.sha256).digest()
                        k_mac = hmac.new(secret_key, b"MAC:" + nonce, hashlib.sha256).digest()
                        expected_tag = hmac.new(k_mac, nonce + ciphertext, hashlib.sha256).hexdigest()
                        if hmac.compare_digest(expected_tag, tag):
                            blocks = (len(ciphertext) + 31) // 32
                            keystream = b"".join(
                                hmac.new(k_enc, i.to_bytes(4, "big"), hashlib.sha256).digest()
                                for i in range(blocks)
                            )
                            plain_bytes = bytes(
                                c ^ k for c, k in zip(ciphertext, keystream[: len(ciphertext)], strict=True)
                            )
                            plaintext = plain_bytes.decode("utf-8")
                except Exception as e:
                    logger.warning("Error migrating legacy enc:v1 secret: %s", e)
                    plaintext = ""

            if plaintext:
                if IS_WINDOWS:
                    try:
                        encrypted = dpapi_protect(plaintext)
                        conn.execute(
                            "UPDATE settings SET value = ?, updated_at = ? WHERE key = 'api_key'",
                            (encrypted, now_iso()),
                        )
                    except Exception:
                        conn.execute("DELETE FROM settings WHERE key = 'api_key'")
                elif keyring:
                    try:
                        keyring.set_password("omnidim_control_center", "api_key", plaintext)
                        conn.execute("DELETE FROM settings WHERE key = 'api_key'")
                    except Exception:
                        conn.execute("DELETE FROM settings WHERE key = 'api_key'")
                else:
                    conn.execute("DELETE FROM settings WHERE key = 'api_key'")
            else:
                conn.execute("DELETE FROM settings WHERE key = 'api_key'")

        if secret_key_file.exists():
            try:
                secret_key_file.unlink()
            except OSError:
                pass
    finally:
        if conn_context:
            conn_context.__exit__(None, None, None)
