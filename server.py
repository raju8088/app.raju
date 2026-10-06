import argparse
import datetime as dt
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:
    import keyring
except ImportError:
    keyring = None

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "omnidim_ui.sqlite3"
SECRET_KEY_FILE = DATA_DIR / ".secret_key"
DEFAULT_BASE_URL = "https://omnidim.io/api/v1"
MAX_LOG_CHARS = 200_000
HISTORY_RETENTION_LIMIT = 500
MAX_REQUEST_BODY_BYTES = 10 * 1024 * 1024  # 10 MB limit

CSRF_TOKEN = secrets.token_hex(32)
LOCAL_AUTH_TOKEN = secrets.token_urlsafe(32)
READ_ONLY_MODE = False

CONFIRMATION_TOKENS = {}  # token -> (timestamp, endpoint_id)
CONFIRMATION_TOKEN_TTL = 60  # seconds

REDACT_KEYS = {
    "password",
    "token",
    "secret",
    "api_key",
    "api_token",
    "auth_token",
    "sip_password",
    "account_sid",
    "authorization",
}



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

STATIC_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


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


def endpoint_id(method, path):
    return re.sub(r"[^a-z0-9]+", "-", f"{method}-{path}".lower()).strip("-")


def ep(group, method, path, summary, body=None, query=None, note="", danger=False):
    method = method.upper()
    return {
        "id": endpoint_id(method, path),
        "group": group,
        "method": method,
        "path": path,
        "summary": summary,
        "bodyExample": body,
        "queryExample": query or {},
        "note": note,
        "danger": danger,
        "pathParams": re.findall(r"{([^}]+)}", path),
    }


GROUPS = [
    {
        "name": "Sessions",
        "description": "Create temporary browser voice sessions and receive a WebSocket URL.",
        "endpoints": [
            ep("Sessions", "POST", "/sessions/create", "Create session", {"agent_id": 158910}),
        ],
    },
    {
        "name": "Agents",
        "description": "Create, inspect, update, delete, and version AI voice agents.",
        "endpoints": [
            ep("Agents", "GET", "/agents", "List agents", query={"pageno": 1, "pagesize": 30}),
            ep(
                "Agents",
                "POST",
                "/agents/create",
                "Create agent",
                {
                    "name": "Customer Support Agent",
                    "welcome_message": "Hello! I am your support assistant. How can I help you today?",
                    "context_breakdown": [
                        {
                            "title": "Purpose",
                            "body": "This agent helps customers with product questions and support issues.",
                        }
                    ],
                },
            ),
            ep("Agents", "GET", "/agents/{agent_id}", "Get agent"),
            ep(
                "Agents",
                "PUT",
                "/agents/{agent_id}",
                "Update agent",
                {
                    "name": "Updated Support Agent",
                    "welcome_message": "Hello! I am your updated support assistant. How can I help you today?",
                    "context_breakdown": [
                        {
                            "title": "Purpose",
                            "body": "This agent helps customers with product questions and support issues.",
                        }
                    ],
                },
            ),
            ep("Agents", "DELETE", "/agents/{agent_id}", "Delete agent", danger=True),
            ep("Agents", "GET", "/agents/{agent_id}/versions", "List agent versions", query={"pageno": 1, "pagesize": 30}),
            ep(
                "Agents",
                "POST",
                "/agents/{agent_id}/versions",
                "Save an agent version",
                {"name": "Working version", "note": "Saved before editing the prompt."},
            ),
            ep(
                "Agents",
                "PATCH",
                "/agents/{agent_id}/versions/{version_number}",
                "Rename an agent version",
                {"name": "Pre-launch version", "note": "Reviewed and renamed."},
            ),
            ep("Agents", "DELETE", "/agents/{agent_id}/versions/{version_number}", "Delete an agent version", danger=True),
            ep("Agents", "GET", "/agents/{agent_id}/versions/{version_number}/diff", "Diff an agent version"),
            ep(
                "Agents",
                "POST",
                "/agents/{agent_id}/versions/{version_number}/restore",
                "Restore an agent version",
                {},
                danger=True,
            ),
        ],
    },
    {
        "name": "Calls",
        "description": "Place one outbound call and review call logs.",
        "endpoints": [
            ep(
                "Calls",
                "POST",
                "/calls/dispatch",
                "Dispatch call",
                {
                    "agent_id": 158910,
                    "to_number": "+15551234567",
                    "from_number_id": 23,
                    "call_context": {
                        "user_name": "Jane Doe",
                        "account_id": "A-2031",
                        "last_order": "2026-04-15",
                    },
                    "metadata": {"crm_lead_id": "lead_9876", "source": "website_form"},
                },
                danger=True,
                note="This can place a real outbound call when your key has call access.",
            ),
            ep("Calls", "GET", "/calls/logs", "List call logs", query={"page": 1, "page_size": 10}),
            ep("Calls", "GET", "/calls/logs/{call_log_id}", "Get call log"),
        ],
    },
    {
        "name": "Bulk Calls",
        "description": "Build and operate campaign calling flows.",
        "endpoints": [
            ep("Bulk Calls", "GET", "/calls/bulk_call", "Fetch bulk calls", query={"pageno": 1, "pagesize": 10, "status": ""}),
            ep(
                "Bulk Calls",
                "POST",
                "/calls/bulk_call/create",
                "Create bulk call",
                {
                    "name": "Customer follow-ups",
                    "phone_number_id": "177",
                    "bot_id": 512,
                    "contact_list": [
                        {"phone_number": "+15551234567", "customer_name": "John Doe", "plan": "pro"},
                        {"phone_number": "+15559876543", "customer_name": "Jane Smith", "plan": "trial"},
                    ],
                    "is_scheduled": False,
                    "concurrent_call_limit": 1,
                    "retry_config": {"auto_retry": False, "auto_retry_schedule": "next_day", "retry_limit": 1},
                },
                danger=True,
            ),
            ep(
                "Bulk Calls",
                "POST",
                "/calls/bulk_call/{campaign_id}/add_contact",
                "Add contact to dynamic campaign",
                {
                    "to_number": "+15551234567",
                    "custom_variables": {"name": "Demo User", "interest": "Home Insurance"},
                    "metadata": {"crm_lead_id": "lead_9876", "source": "website_form"},
                },
                danger=True,
            ),
            ep("Bulk Calls", "GET", "/calls/bulk_call/{bulk_call_id}", "Bulk call details"),
            ep("Bulk Calls", "PUT", "/calls/bulk_call/{bulk_call_id}", "Bulk call actions", {"action": "pause"}),
            ep("Bulk Calls", "DELETE", "/calls/bulk_call/{bulk_call_id}", "Cancel bulk call", danger=True),
            ep("Bulk Calls", "GET", "/calls/bulk_call/{bulk_call_id}/lines", "Bulk call results", query={"pagesize": 150, "include_total": True}),
            ep("Bulk Calls", "GET", "/calls/bulk_call/{bulk_call_id}/numbers", "List rotation pool"),
            ep("Bulk Calls", "POST", "/calls/bulk_call/{bulk_call_id}/numbers", "Add number to rotation pool", {"phone_number_id": 178}),
            ep(
                "Bulk Calls",
                "PUT",
                "/calls/bulk_call/{bulk_call_id}/numbers/{assignment_id}",
                "Pause or resume pool number",
                {"is_active": False},
            ),
            ep(
                "Bulk Calls",
                "POST",
                "/calls/bulk_call/{campaign_id}/add_contacts",
                "Add contacts in bulk",
                {
                    "contacts": [
                        {"to_number": "+15551234567", "custom_variables": {"contact_name": "Ravi"}},
                        {"to_number": "+15559876543", "custom_variables": {"contact_name": "Priya"}},
                    ]
                },
                danger=True,
            ),
            ep("Bulk Calls", "POST", "/calls/bulk_call/{bulk_call_id}/start", "Start a draft campaign", {}, danger=True),
            ep("Bulk Calls", "PUT", "/calls/bulk_call/{bulk_call_id}/concurrency", "Change concurrency", {"concurrent_call_limit": 5}),
            ep(
                "Bulk Calls",
                "POST",
                "/calls/bulk_call/{bulk_call_id}/manual_retry",
                "Retry contacts that did not connect",
                {"line_ids": [156], "retry_after_minutes": 15},
                danger=True,
            ),
            ep(
                "Bulk Calls",
                "PUT",
                "/calls/bulk_call/{bulk_call_id}/daily-time-control",
                "Set calling hours",
                {
                    "enable_daily_auto_start": True,
                    "daily_start_time": "09:00",
                    "daily_start_timezone": "America/New_York",
                    "enable_daily_hard_stop": True,
                    "daily_stop_time": "17:00",
                    "daily_stop_timezone": "America/New_York",
                },
            ),
            ep("Bulk Calls", "GET", "/bulk-call/{bulk_call_id}/live-status", "Bulk call live status"),
        ],
    },
    {
        "name": "Knowledge Base",
        "description": "Upload PDF knowledge files and attach them to agents.",
        "endpoints": [
            ep("Knowledge Base", "GET", "/knowledge_base/list", "List knowledge base files"),
            ep("Knowledge Base", "POST", "/knowledge_base/can_upload", "Check file upload capability", {"file_size": 1048576, "file_type": "application/pdf"}),
            ep(
                "Knowledge Base",
                "POST",
                "/knowledge_base/create",
                "Upload file to knowledge base",
                {"file": "BASE64_PDF_CONTENT", "filename": "sample.pdf"},
                note="Use the file helper in the UI to load a PDF into the JSON body.",
            ),
            ep(
                "Knowledge Base",
                "POST",
                "/knowledge_base/attach",
                "Attach files to agent",
                {"file_ids": [123, 456], "agent_id": 789, "access_description": "Use these files when answering policy questions."},
            ),
            ep("Knowledge Base", "POST", "/knowledge_base/detach", "Detach files from agent", {"file_ids": [123, 456], "agent_id": 789}),
            ep("Knowledge Base", "POST", "/knowledge_base/delete", "Delete file from knowledge base", {"file_id": 123}, danger=True),
        ],
    },
    {
        "name": "Phone Numbers",
        "description": "List, buy, import, attach, and release calling numbers.",
        "endpoints": [
            ep("Phone Numbers", "GET", "/phone_number/list", "List phone numbers", query={"pageno": 1, "pagesize": 30}),
            ep("Phone Numbers", "GET", "/phone_number/search", "Search available phone numbers", query={"region": "US", "carrier": "carrier-1", "pattern": "", "page": 1, "limit": 20}),
            ep(
                "Phone Numbers",
                "POST",
                "/phone_number/purchase",
                "Purchase a phone number",
                {"phone_number": "+15551234567", "region": "US", "carrier": "carrier-1"},
                danger=True,
            ),
            ep("Phone Numbers", "POST", "/phone_number/release", "Release a phone number", {"phone_number_id": 213}, danger=True),
            ep("Phone Numbers", "POST", "/phone_number/attach", "Attach phone number to agent", {"phone_number_id": 213, "agent_id": 158910}),
            ep("Phone Numbers", "POST", "/phone_number/detach", "Detach phone number", {"phone_number_id": 213}),
            ep(
                "Phone Numbers",
                "POST",
                "/phone_number/import/twilio",
                "Import Twilio number",
                {"phone_number": "+15551234567", "account_sid": "ACxxxxxxxx", "auth_token": "twilio_auth_token"},
                danger=True,
            ),
            ep(
                "Phone Numbers",
                "POST",
                "/phone_number/import/exotel",
                "Import Exotel number",
                {
                    "phone_number": "+911234567890",
                    "subdomain": "your-subdomain",
                    "account_sid": "exotel_account_sid",
                    "api_key": "exotel_api_key",
                    "api_token": "exotel_api_token",
                },
                danger=True,
            ),
            ep(
                "Phone Numbers",
                "POST",
                "/phone_number/import/sip",
                "Import SIP trunk",
                {
                    "phone_number": "+15551234567",
                    "sip_host": "sip.example.com",
                    "sip_port": 5060,
                    "sip_username": "username",
                    "sip_password": "password",
                    "sip_trunk_name": "Main trunk",
                },
                danger=True,
            ),
        ],
    },
    {
        "name": "Providers",
        "description": "Discover available LLM, speech-to-text, text-to-speech, and voice options.",
        "endpoints": [
            ep("Providers", "GET", "/providers/llms", "List LLM providers"),
            ep("Providers", "GET", "/providers/voices", "List voices", query={"provider": "", "language": ""}),
            ep("Providers", "GET", "/providers/stt", "List STT providers"),
            ep("Providers", "GET", "/providers/tts", "List TTS providers"),
            ep("Providers", "GET", "/providers/all", "List all providers"),
            ep("Providers", "GET", "/providers/voice/{voice_id}", "Get voice details"),
        ],
    },
    {
        "name": "Simulation",
        "description": "Create and run tests against agents before live calling.",
        "endpoints": [
            ep("Simulation", "GET", "/simulations", "List simulations", query={"page": 1, "page_size": 30}),
            ep(
                "Simulation",
                "POST",
                "/simulations",
                "Create simulation",
                {
                    "name": "Customer Support Test",
                    "agent_id": 158910,
                    "number_of_call_to_make": 1,
                    "concurrent_call_count": 1,
                    "max_call_duration_in_minutes": 3,
                    "scenarios": [
                        {
                            "name": "Polite cancellation",
                            "description": "Ask to cancel a subscription, but be friendly.",
                            "expected_result": "Agent acknowledges the request and routes to retention.",
                            "selected_voices": [{"id": "voice_id_1", "provider": "eleven_labs"}],
                        }
                    ],
                },
            ),
            ep("Simulation", "GET", "/simulations/{simulation_id}", "Get simulation"),
            ep(
                "Simulation",
                "PUT",
                "/simulations/{simulation_id}",
                "Update simulation",
                {"name": "Updated Support Test", "number_of_call_to_make": 1, "concurrent_call_count": 1},
            ),
            ep("Simulation", "DELETE", "/simulations/{simulation_id}", "Delete simulation", danger=True),
            ep("Simulation", "POST", "/simulations/{simulation_id}/start", "Start simulation", {}, danger=True),
            ep("Simulation", "POST", "/simulations/{simulation_id}/stop", "Stop simulation", {}),
            ep("Simulation", "POST", "/simulations/{simulation_id}/enhance-prompt", "Enhance prompt", {"prompt": "Make this test more realistic."}),
        ],
    },
    {
        "name": "Reseller/Admin",
        "description": "Manage child organizations, credits, concurrency, and KYC flows.",
        "endpoints": [
            ep("Reseller/Admin", "GET", "/reseller/organizations", "List child organizations", query={"page": 1, "page_size": 30}),
            ep(
                "Reseller/Admin",
                "POST",
                "/reseller/users/add",
                "Add user",
                {"name": "Demo User", "email": "demo@example.com", "password": "temporary-password"},
                danger=True,
            ),
            ep("Reseller/Admin", "POST", "/reseller/users/access-control", "Update user access control", {"user_id": 1234, "access": {"is_bots_menu_access": True}}, danger=True),
            ep("Reseller/Admin", "POST", "/reseller/users/expiry", "Update user expiry", {"user_id": 1234, "expiry_date": "2026-12-31"}, danger=True),
            ep("Reseller/Admin", "POST", "/reseller/concurrency", "Set child concurrency limit", {"user_id": 1234, "concurrent_call_limit": 3}, danger=True),
            ep("Reseller/Admin", "POST", "/reseller/credits/calculate", "Calculate credit operation", {"user_id": 1234, "credits": 100}),
            ep("Reseller/Admin", "POST", "/reseller/credits/transfer", "Transfer credits to a child", {"user_id": 1234, "credits": 100}, danger=True),
            ep("Reseller/Admin", "POST", "/reseller/credits/revert", "Revert credits", {"user_id": 1234, "credits": 50}, danger=True),
            ep("Reseller/Admin", "GET", "/reseller/credits/logs", "Credit transfer logs", query={"page": 1, "page_size": 30}),
            ep("Reseller/Admin", "GET", "/reseller/kyc/status", "Get KYC status", query={"user_id": 1234}),
            ep("Reseller/Admin", "GET", "/reseller/kyc/requirements", "Get KYC requirements for a region", query={"region": "US", "carrier": "carrier-1"}),
            ep(
                "Reseller/Admin",
                "POST",
                "/reseller/kyc/steps/{step}",
                "Submit a KYC verification step",
                {"user_id": 1234, "region": "US", "carrier": "carrier-1", "name": "Demo User", "email": "demo@example.com", "phone": "+15551234567"},
                danger=True,
            ),
        ],
    },
]


ENDPOINTS = [endpoint for group in GROUPS for endpoint in group["endpoints"]]

_TEMPLATE_REGEX_CACHE = {}


def template_to_regex(template: str):
    if template not in _TEMPLATE_REGEX_CACHE:
        pattern = "^" + re.sub(r"\{([^}]+)\}", r"(?P<\1>[^/?#]+)", template) + "$"
        _TEMPLATE_REGEX_CACHE[template] = re.compile(pattern)
    return _TEMPLATE_REGEX_CACHE[template]


def match_endpoint(method: str, path: str):
    method = method.upper()
    if ".." in path or "?" in path or "#" in path:
        raise ValueError(f"Path contains illegal characters: {path}")
    for endpoint in ENDPOINTS:
        if endpoint["method"] != method:
            continue
        regex = template_to_regex(endpoint["path"])
        m = regex.fullmatch(path)
        if m:
            params = m.groupdict()
            for name, val in params.items():
                if any(c in val for c in ("/", "..", "?", "#")) or any(ord(c) < 32 or ord(c) == 127 for c in val):
                    raise ValueError(f"Path parameter '{name}' contains illegal characters: {val}")
            return endpoint, params
    return None, {}


def now_iso():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def compact_json(value):
    text = json.dumps(value, ensure_ascii=True, separators=(",", ":")) if not isinstance(value, str) else value
    if len(text) > MAX_LOG_CHARS:
        return text[:MAX_LOG_CHARS] + "\n... truncated ..."
    return text


def get_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS request_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id TEXT,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                url TEXT NOT NULL,
                status INTEGER,
                ok INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL,
                request_json TEXT,
                response_json TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS saved_payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id TEXT NOT NULL,
                name TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                query_json TEXT NOT NULL,
                body_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        conn.execute(
            "INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
            ("base_url", DEFAULT_BASE_URL, now_iso()),
        )


def get_or_create_master_key() -> bytes:
    """Retrieve or generate local master secret key with 0600 permissions."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not SECRET_KEY_FILE.exists():
        key = secrets.token_bytes(32)
        SECRET_KEY_FILE.write_bytes(key)
        try:
            os.chmod(SECRET_KEY_FILE, 0o600)
        except (OSError, NotImplementedError):
            pass
        return key
    try:
        os.chmod(SECRET_KEY_FILE, 0o600)
    except (OSError, NotImplementedError):
        pass
    return SECRET_KEY_FILE.read_bytes()[:32]


def encrypt_secret(plaintext: str) -> str:
    """Encrypt secret string using authenticated encryption (HMAC-SHA256 Encrypt-then-MAC)."""
    if not plaintext:
        return ""
    master_key = get_or_create_master_key()
    nonce = secrets.token_bytes(16)
    k_enc = hmac.new(master_key, b"ENC:" + nonce, hashlib.sha256).digest()
    k_mac = hmac.new(master_key, b"MAC:" + nonce, hashlib.sha256).digest()

    plain_bytes = plaintext.encode("utf-8")
    blocks = (len(plain_bytes) + 31) // 32
    keystream = b"".join(
        hmac.new(k_enc, i.to_bytes(4, "big"), hashlib.sha256).digest()
        for i in range(blocks)
    )
    ciphertext = bytes(p ^ k for p, k in zip(plain_bytes, keystream[: len(plain_bytes)], strict=True))
    tag = hmac.new(k_mac, nonce + ciphertext, hashlib.sha256).hexdigest()
    return f"enc:v1:{nonce.hex()}:{ciphertext.hex()}:{tag}"


def decrypt_secret(stored_val: str) -> str:
    """Decrypt secret string, verifying authenticity in constant time."""
    if not stored_val or not stored_val.startswith("enc:v1:"):
        return stored_val  # Support legacy plaintext fallback
    parts = stored_val.split(":")
    if len(parts) != 5:
        return ""
    _, _, nonce_hex, ciphertext_hex, expected_tag = parts
    try:
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
    except ValueError:
        return ""

    master_key = get_or_create_master_key()
    k_enc = hmac.new(master_key, b"ENC:" + nonce, hashlib.sha256).digest()
    k_mac = hmac.new(master_key, b"MAC:" + nonce, hashlib.sha256).digest()

    actual_tag = hmac.new(k_mac, nonce + ciphertext, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(actual_tag, expected_tag):
        return ""

    blocks = (len(ciphertext) + 31) // 32
    keystream = b"".join(
        hmac.new(k_enc, i.to_bytes(4, "big"), hashlib.sha256).digest()
        for i in range(blocks)
    )
    plain_bytes = bytes(c ^ k for c, k in zip(ciphertext, keystream[: len(ciphertext)], strict=True))

    try:
        return plain_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def issue_confirm_token(endpoint_id: str) -> str:
    """Issue a single-use confirmation token for a dangerous action."""
    now = time.time()
    expired = [k for k, (ts, _) in CONFIRMATION_TOKENS.items() if now - ts > CONFIRMATION_TOKEN_TTL]
    for k in expired:
        CONFIRMATION_TOKENS.pop(k, None)
    token = secrets.token_hex(16)
    CONFIRMATION_TOKENS[token] = (now, endpoint_id)
    return token


def consume_confirm_token(token: str, endpoint_id: str) -> bool:
    """Validate and consume a single-use confirmation token."""
    now = time.time()
    if token in CONFIRMATION_TOKENS:
        ts, ep_id = CONFIRMATION_TOKENS.pop(token)
        if now - ts <= CONFIRMATION_TOKEN_TTL and ep_id == endpoint_id:
            return True
    return False


def get_api_key():
    # 1. Environment variable has highest priority
    env_key = os.environ.get("OMNIDIM_API_KEY", "").strip()
    if env_key:
        return env_key, "env"

    # 2. OS Keyring if available
    if keyring:
        try:
            kr_key = keyring.get_password("omnidim_control_center", "api_key")
            if kr_key and kr_key.strip():
                return kr_key.strip(), "keyring"
        except Exception:
            pass

    # 3. SQLite settings table (encrypted at rest)
    with get_db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = 'api_key'").fetchone()
        if row and row["value"]:
            decrypted = decrypt_secret(row["value"].strip())
            if decrypted:
                return decrypted, "db"

    return "", "none"


def secure_db_file():
    for f in (DB_PATH, SECRET_KEY_FILE):
        if f.exists():
            try:
                os.chmod(f, 0o600)
            except (OSError, NotImplementedError):
                pass


def read_settings(include_secret=False):
    with get_db() as conn:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
    raw = {row["key"]: row["value"] for row in rows}
    api_key, source = get_api_key()

    if source == "env":
        notice = "API key loaded from OMNIDIM_API_KEY environment variable (recommended)."
    elif source == "keyring":
        notice = "API key loaded from OS Keychain via keyring (secure)."
    elif source == "db":
        notice = (
            "API key stored encrypted at rest in local SQLite (derived from local 0600 secret file). "
            "Note: local root/user filesystem access can read the secret key file. "
            "Using OS keyring or OMNIDIM_API_KEY environment variable is recommended."
        )
    else:
        notice = "No API key configured. Provide OMNIDIM_API_KEY in environment or save via UI."

    data = {
        "baseUrl": raw.get("base_url", DEFAULT_BASE_URL),
        "hasApiKey": bool(api_key),
        "apiKeySource": source,
        "apiKeyPreview": f"...{api_key[-4:]}" if api_key else "",
        "securityNotice": notice,
        "retentionLimit": HISTORY_RETENTION_LIMIT,
        "readOnly": READ_ONLY_MODE,
    }
    if include_secret:
        data["apiKey"] = api_key
    return data


def save_setting(key, value):
    stored_val = encrypt_secret(value) if key == "api_key" else value
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, stored_val, now_iso()),
        )
    if key == "api_key":
        secure_db_file()



def delete_setting(key):
    with get_db() as conn:
        conn.execute("DELETE FROM settings WHERE key = ?", (key,))


def build_url(base_url, path, query):
    base = base_url.rstrip("/")
    parsed_pairs = []
    for key, value in (query or {}).items():
        if value is None or value == "":
            continue
        if isinstance(value, list):
            for item in value:
                if item is not None and item != "":
                    parsed_pairs.append((key, item))
        else:
            parsed_pairs.append((key, value))
    suffix = urllib.parse.urlencode(parsed_pairs, doseq=True)
    return f"{base}{path}" + (f"?{suffix}" if suffix else "")


def parse_json_bytes(raw):
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc


def log_history(endpoint_id_value, method, path, url, status, ok, duration_ms, request_payload, response_payload):
    clean_url = sanitize_url(url)
    redacted_req = redact_payload(request_payload)
    redacted_res = redact_payload(response_payload)
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO request_history
            (endpoint_id, method, path, url, status, ok, duration_ms, request_json, response_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                endpoint_id_value,
                method,
                path,
                clean_url,
                status,
                1 if ok else 0,
                duration_ms,
                compact_json(redacted_req),
                compact_json(redacted_res),
                now_iso(),
            ),
        )
        # Auto-prune to keep only the last HISTORY_RETENTION_LIMIT records
        conn.execute(
            """
            DELETE FROM request_history
            WHERE id NOT IN (
                SELECT id FROM request_history ORDER BY id DESC LIMIT ?
            )
            """,
            (HISTORY_RETENTION_LIMIT,),
        )


class AppHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(405)
        self.send_header("Allow", "GET, POST, PUT, PATCH, DELETE")
        self.end_headers()

    def do_GET(self):
        self.route()

    def do_POST(self):
        self.route()

    def do_PUT(self):
        self.route()

    def do_PATCH(self):
        self.route()

    def do_DELETE(self):
        self.route()

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")

    def is_authenticated(self) -> bool:
        token_hdr = self.headers.get("X-Local-Token", "").strip()
        if token_hdr and hmac.compare_digest(token_hdr, LOCAL_AUTH_TOKEN):
            return True
        cookie_hdr = self.headers.get("Cookie", "")
        if cookie_hdr:
            for item in cookie_hdr.split(";"):
                parts = item.strip().split("=", 1)
                if len(parts) == 2 and parts[0].strip() == "local_token":
                    if hmac.compare_digest(parts[1].strip(), LOCAL_AUTH_TOKEN):
                        return True
        return False

    def route(self):
        req_id = uuid.uuid4().hex[:12]
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        try:
            if path.startswith("/api/"):
                # 1. Host header validation
                host_header = self.headers.get("Host", "")
                if not is_valid_host(host_header):
                    self.send_json(
                        {"ok": False, "error": "Invalid or forbidden Host header", "requestId": req_id},
                        status=403,
                    )
                    return

                # 2. Local auth token check
                if not self.is_authenticated():
                    self.send_json(
                        {
                            "ok": False,
                            "error": "Unauthorized: valid local auth token required in X-Local-Token header or cookie",
                            "requestId": req_id,
                        },
                        status=401,
                    )
                    return

                # 3. Read-only mode enforcement
                if READ_ONLY_MODE and self.command != "GET":
                    self.send_json(
                        {
                            "ok": False,
                            "error": "Server is running in read-only mode. Mutating actions are blocked.",
                            "requestId": req_id,
                        },
                        status=403,
                    )
                    return

                # 4. Mutating requests validation (POST, PUT, PATCH, DELETE)
                if self.command in {"POST", "PUT", "PATCH", "DELETE"}:
                    content_type = self.headers.get("Content-Type", "")
                    if not content_type.lower().startswith("application/json"):
                        self.send_json(
                            {"ok": False, "error": "Content-Type must be application/json", "requestId": req_id},
                            status=415,
                        )
                        return

                    origin = self.headers.get("Origin", "")
                    if not is_valid_origin(origin):
                        self.send_json(
                            {"ok": False, "error": "Cross-origin request forbidden", "requestId": req_id},
                            status=403,
                        )
                        return

                    csrf_token = self.headers.get("X-CSRF-Token", "")
                    if not is_valid_csrf(csrf_token):
                        self.send_json(
                            {"ok": False, "error": "Invalid or missing CSRF token", "requestId": req_id},
                            status=403,
                        )
                        return

                self.route_api(path, parsed, req_id)
                return
            self.serve_static(path)
        except ValueError as exc:
            print(f"[{req_id}] Validation error on {self.command} {path}: {exc}")
            self.send_json({"ok": False, "error": str(exc), "requestId": req_id}, status=400)
        except Exception:  # noqa: BLE001
            print(f"[{req_id}] Server error on {self.command} {path}: {traceback.format_exc()}")
            self.send_json({"ok": False, "error": "Internal server error", "requestId": req_id}, status=500)

    def route_api(self, path, parsed, req_id):
        if path == "/api/session" and self.command == "GET":
            self.send_json({"ok": True, "csrfToken": CSRF_TOKEN, "localToken": LOCAL_AUTH_TOKEN})
            return

        if path == "/api/health" and self.command == "GET":
            self.send_json(
                {
                    "ok": True,
                    "time": now_iso(),
                    "database": str(DB_PATH),
                    "endpointCount": len(ENDPOINTS),
                    "readOnly": READ_ONLY_MODE,
                }
            )
            return


        if path == "/api/endpoints" and self.command == "GET":
            self.send_json({"groups": GROUPS, "endpoints": ENDPOINTS})
            return

        if path == "/api/settings":
            if self.command == "GET":
                self.send_json(read_settings())
                return
            if self.command in {"POST", "PUT"}:
                data = self.read_json()
                base_url = data.get("baseUrl", "").strip()
                api_key = data.get("apiKey", "").strip()
                if base_url:
                    if not base_url.startswith("https://"):
                        raise ValueError("Base URL must start with https://")
                    save_setting("base_url", base_url.rstrip("/"))
                if api_key:
                    if keyring:
                        try:
                            keyring.set_password("omnidim_control_center", "api_key", api_key)
                        except Exception:
                            pass
                    save_setting("api_key", api_key)
                    secure_db_file()
                self.send_json(read_settings())
                return

        if path == "/api/settings/api-key" and self.command == "DELETE":
            if keyring:
                try:
                    keyring.delete_password("omnidim_control_center", "api_key")
                except Exception:
                    pass
            delete_setting("api_key")
            self.send_json(read_settings())
            return

        if path == "/api/history":
            if self.command == "GET":
                query = urllib.parse.parse_qs(parsed.query)
                limit = int(query.get("limit", ["80"])[0])
                limit = max(1, min(limit, 250))
                with get_db() as conn:
                    rows = conn.execute(
                        """
                        SELECT * FROM request_history
                        ORDER BY id DESC
                        LIMIT ?
                        """,
                        (limit,),
                    ).fetchall()
                self.send_json({"records": [dict(row) for row in rows]})
                return
            if self.command == "DELETE":
                with get_db() as conn:
                    conn.execute("DELETE FROM request_history")
                    conn.execute("VACUUM")
                self.send_json({"ok": True, "message": "History cleared successfully"})
                return

        if path == "/api/saved-payloads":
            if self.command == "GET":
                query = urllib.parse.parse_qs(parsed.query)
                endpoint_filter = query.get("endpoint_id", [""])[0]
                with get_db() as conn:
                    if endpoint_filter:
                        rows = conn.execute(
                            "SELECT * FROM saved_payloads WHERE endpoint_id = ? ORDER BY updated_at DESC",
                            (endpoint_filter,),
                        ).fetchall()
                    else:
                        rows = conn.execute("SELECT * FROM saved_payloads ORDER BY updated_at DESC").fetchall()
                self.send_json({"records": [dict(row) for row in rows]})
                return
            if self.command == "POST":
                data = self.read_json()
                required = ["endpoint_id", "name", "method", "path"]
                missing = [key for key in required if not data.get(key)]
                if missing:
                    raise ValueError(f"Missing fields: {', '.join(missing)}")
                ts = now_iso()
                sanitized_query = redact_payload(data.get("query", {}))
                sanitized_body = redact_payload(data.get("body", {}))
                with get_db() as conn:
                    cur = conn.execute(
                        """
                        INSERT INTO saved_payloads
                        (endpoint_id, name, method, path, query_json, body_json, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            data["endpoint_id"],
                            data["name"],
                            data["method"],
                            data["path"],
                            compact_json(sanitized_query),
                            compact_json(sanitized_body),
                            ts,
                            ts,
                        ),
                    )
                self.send_json({"ok": True, "id": cur.lastrowid})
                return

        saved_match = re.fullmatch(r"/api/saved-payloads/(\d+)", path)
        if saved_match and self.command == "DELETE":
            with get_db() as conn:
                conn.execute("DELETE FROM saved_payloads WHERE id = ?", (int(saved_match.group(1)),))
            self.send_json({"ok": True})
            return

        if path == "/api/run" and self.command == "POST":
            self.run_omni_request(req_id)
            return

        self.send_json({"ok": False, "error": "Not found", "requestId": req_id}, status=404)

    def run_omni_request(self, req_id):
        data = self.read_json()
        method = data.get("method", "GET").upper()
        path = data.get("path", "")
        query = data.get("query") or {}
        body = data.get("body", None)
        confirm = data.get("confirm", "").strip()

        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("Unsupported HTTP method")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("Path must start with /")
        if "://" in path:
            raise ValueError("Path must be relative to the OmniDimension API base URL")
        if not isinstance(query, dict):
            raise ValueError("Query must be a JSON object")

        # 1. Match against registered endpoint allowlist
        matched_endpoint, path_params = match_endpoint(method, path)
        if not matched_endpoint:
            self.send_json(
                {
                    "ok": False,
                    "error": f"Endpoint {method} {path} is not in the registered API allowlist.",
                    "requestId": req_id,
                },
                status=403,
            )
            return

        endpoint_id_value = data.get("endpointId", matched_endpoint["id"])

        # 2. Server-side enforcement of danger flag
        if matched_endpoint.get("danger"):
            expected_summary = matched_endpoint["summary"].strip()
            is_confirmed = False
            confirm_token = data.get("confirmToken", "").strip()
            if confirm_token and consume_confirm_token(confirm_token, matched_endpoint["id"]):
                is_confirmed = True
            elif data.get("confirmed") is True:
                is_confirmed = True
            elif confirm == expected_summary:
                is_confirmed = True

            if not is_confirmed:
                token = issue_confirm_token(matched_endpoint["id"])
                self.send_json(
                    {
                        "ok": False,
                        "error": f"Dangerous action requires explicit confirmation for '{expected_summary}'",
                        "danger": True,
                        "requiredConfirm": expected_summary,
                        "confirmToken": token,
                        "requestId": req_id,
                    },
                    status=428,
                )
                return

        settings = read_settings(include_secret=True)
        api_key = settings.get("apiKey", "")
        if not api_key:
            self.send_json(
                {
                    "ok": False,
                    "error": "Save your OmniDimension API key before sending requests.",
                    "requestId": req_id,
                },
                status=400,
            )
            return

        url = build_url(settings["baseUrl"], path, query)
        started = time.perf_counter()
        request_payload = {"method": method, "path": path, "query": query, "body": body}
        status = None
        ok = False
        response_payload = None

        try:
            payload_bytes = None
            headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
            if method != "GET" and body is not None:
                payload_bytes = json.dumps(body).encode("utf-8")
                headers["Content-Type"] = "application/json"

            request = urllib.request.Request(url, data=payload_bytes, headers=headers, method=method)
            with urllib.request.urlopen(request, timeout=60) as response:
                status = response.status
                raw = response.read()
                response_payload = self.decode_response(raw, response.headers.get_content_charset())
                ok = 200 <= status < 300
        except urllib.error.HTTPError as exc:
            status = exc.code
            raw = exc.read()
            response_payload = self.decode_response(raw, exc.headers.get_content_charset())
            ok = False
        except urllib.error.URLError as exc:
            response_payload = {"error": "Network error", "detail": str(exc.reason)}
            ok = False
        except TimeoutError:
            response_payload = {"error": "Timeout", "detail": "The OmniDimension API request took too long."}
            ok = False

        duration_ms = int((time.perf_counter() - started) * 1000)
        log_history(endpoint_id_value, method, path, url, status, ok, duration_ms, request_payload, response_payload)
        self.send_json(
            {
                "ok": ok,
                "status": status,
                "durationMs": duration_ms,
                "url": url,
                "data": response_payload,
            },
            status=200 if status is None or status < 500 else 502,
        )

    def decode_response(self, raw, charset):
        if not raw:
            return None
        text = raw.decode(charset or "utf-8", errors="replace")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

    def read_json(self):
        length_str = self.headers.get("Content-Length", "0")
        try:
            length = int(length_str)
        except ValueError as exc:
            raise ValueError("Invalid Content-Length header") from exc

        if length > MAX_REQUEST_BODY_BYTES:
            raise ValueError(f"Request body exceeds maximum allowed size ({MAX_REQUEST_BODY_BYTES} bytes)")
        return parse_json_bytes(self.rfile.read(length))

    def serve_static(self, path):
        if path in {"", "/"}:
            file_path = (STATIC_DIR / "index.html").resolve()
        else:
            requested = path.lstrip("/")
            if requested.startswith("static/"):
                requested = requested[len("static/") :]
            file_path = (STATIC_DIR / requested).resolve()
            try:
                if not file_path.is_relative_to(STATIC_DIR.resolve()):
                    self.send_error(403)
                    return
            except (ValueError, AttributeError):
                self.send_error(403)
                return

            if not file_path.exists() or not file_path.is_file():
                file_path = (STATIC_DIR / "index.html").resolve()

        content_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        data = file_path.read_bytes()

        if file_path.name == "index.html":
            html_text = data.decode("utf-8", errors="replace")
            meta_tags = (
                f'<meta name="csrf-token" content="{CSRF_TOKEN}">\n'
                f'    <meta name="local-token" content="{LOCAL_AUTH_TOKEN}">'
            )
            if '<meta name="csrf-token"' in html_text:
                html_text = re.sub(r'<meta name="csrf-token"[^>]*>', meta_tags, html_text)
            else:
                html_text = html_text.replace("</head>", f"    {meta_tags}\n  </head>")
            data = html_text.encode("utf-8")

        self.send_response(200)
        content_header = (
            f"{content_type}; charset=utf-8"
            if ("text" in content_type or "json" in content_type)
            else content_type
        )
        self.send_header("Content-Type", content_header)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Set-Cookie",
            f"local_token={LOCAL_AUTH_TOKEN}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400",
        )
        for hdr, val in STATIC_SECURITY_HEADERS.items():
            self.send_header(hdr, val)
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, value, status=200):
        data = json.dumps(value, ensure_ascii=True, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for hdr, val in STATIC_SECURITY_HEADERS.items():
            self.send_header(hdr, val)
        self.end_headers()
        self.wfile.write(data)


def main():
    global READ_ONLY_MODE
    parser = argparse.ArgumentParser(description="OmniDimension Control Center")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--read-only", action="store_true", help="Run server in read-only mode")
    args = parser.parse_args()

    if args.read_only:
        READ_ONLY_MODE = True

    if args.host not in {"127.0.0.1", "localhost"}:
        print("\n" + "!" * 78)
        print(f"WARNING: Binding to non-local host '{args.host}'.")
        print("THIS APPLICATION IS INTENDED ONLY FOR LOCALHOST ACCESS!")
        print("!" * 78 + "\n")

    init_db()
    secure_db_file()
    server = ThreadingHTTPServer((args.host, args.port), AppHandler)
    print("\n" + "=" * 78)
    print("OmniDimension Control Center")
    print(f"URL:              http://{args.host}:{args.port}")
    print(f"Browser URL:      http://{args.host}:{args.port}/#token={LOCAL_AUTH_TOKEN}")
    print(f"Local Auth Token: {LOCAL_AUTH_TOKEN}")
    print(f"Mode:             {'READ-ONLY' if READ_ONLY_MODE else 'STANDARD'}")
    print(f"Database:         {DB_PATH}")
    print("=" * 78 + "\n")
    server.serve_forever()


if __name__ == "__main__":
    main()

