from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "omnidim_ui.sqlite3"

# Network & Proxy defaults
DEFAULT_BASE_URL = "https://omnidim.io/api/v1"
PROXY_TIMEOUT_SECONDS = 30
PROXY_MAX_RETRIES = 3
PROXY_RETRY_BACKOFF_FACTOR = 0.5  # 0.5s, 1.0s, 2.0s

# Logging & Limits
MAX_LOG_CHARS = 200_000
HISTORY_RETENTION_LIMIT = 5000
MAX_REQUEST_BODY_BYTES = 10 * 1024 * 1024  # 10 MB limit
CONFIRMATION_TOKEN_TTL = 60  # seconds

# Global Server Flags
READ_ONLY_MODE = False

# Redaction Keys for Logs, History, and URLs
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

# Static Security Headers
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
