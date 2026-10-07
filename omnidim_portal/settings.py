"""Explicit, fail-closed hosted configuration. See DEPLOYMENT.md."""
import os
from pathlib import Path
from urllib.parse import unquote, urlsplit

from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent
DEVELOPMENT = os.environ.get("OMNIDIM_ENV") == "development"
DEBUG = DEVELOPMENT
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "")
if len(SECRET_KEY) < 50:
    raise ImproperlyConfigured("Set DJANGO_SECRET_KEY to a random secret of at least 50 characters.")
if not os.environ.get("OMNIDIM_ENCRYPTION_KEY"):
    raise ImproperlyConfigured("Set OMNIDIM_ENCRYPTION_KEY to a persistent Fernet key.")
try:
    Fernet(os.environ["OMNIDIM_ENCRYPTION_KEY"].encode())
except (ValueError, TypeError) as exc:
    raise ImproperlyConfigured("OMNIDIM_ENCRYPTION_KEY must be a valid Fernet key.") from exc

ALLOWED_HOSTS = [host.strip() for host in os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1" if DEVELOPMENT else "").split(",") if host.strip()]
if not ALLOWED_HOSTS or any(host == "*" or "://" in host for host in ALLOWED_HOSTS):
    raise ImproperlyConfigured("Set explicit ALLOWED_HOSTS; wildcards and URLs are forbidden.")
CSRF_TRUSTED_ORIGINS = [origin.strip() for origin in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split(",") if origin.strip()]
if not DEVELOPMENT and any(not origin.startswith("https://") or "*" in origin for origin in CSRF_TRUSTED_ORIGINS):
    raise ImproperlyConfigured("Production CSRF_TRUSTED_ORIGINS must be explicit HTTPS origins.")

INSTALLED_APPS = [
    "django.contrib.admin", "django.contrib.auth", "django.contrib.contenttypes",
    "django.contrib.sessions", "django.contrib.messages", "django.contrib.staticfiles", "portal_core", "omnidim_portal",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "omnidim_portal.middleware.RequestBoundaryMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
ROOT_URLCONF = "omnidim_portal.urls"
WSGI_APPLICATION = "omnidim_portal.wsgi.application"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [BASE_DIR / "templates"], "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request", "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
}]

database_url = os.environ.get("DATABASE_URL", "")
if database_url:
    parsed = urlsplit(database_url)
    if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname or not parsed.path.strip("/"):
        raise ImproperlyConfigured("DATABASE_URL must identify a PostgreSQL database.")
    DATABASES = {"default": {
        "ENGINE": "django.db.backends.postgresql", "NAME": unquote(parsed.path.lstrip("/")),
        "USER": unquote(parsed.username or ""), "PASSWORD": unquote(parsed.password or ""),
        "HOST": parsed.hostname, "PORT": parsed.port or 5432,
        "CONN_MAX_AGE": 0 if os.environ.get("VERCEL") == "1" else 60, "CONN_HEALTH_CHECKS": True,
        "OPTIONS": {"sslmode": os.environ.get("DATABASE_SSLMODE", "require"), "connect_timeout": 5, "prepare_threshold": None},
    }}
elif DEVELOPMENT:
    DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": os.environ.get("PORTAL_DB_PATH", str(BASE_DIR / "data" / "portal.sqlite3")), "OPTIONS": {"timeout": 10}}}
else:
    raise ImproperlyConfigured("DATABASE_URL is required in production; SQLite is development-only.")

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/login/"
SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_NAME = "omni_session"
SESSION_COOKIE_AGE = 1800
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = not DEVELOPMENT
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = not DEVELOPMENT
CSRF_COOKIE_HTTPONLY = True
CSRF_HEADER_NAME = "HTTP_X_CSRF_TOKEN"
CSRF_FAILURE_VIEW = "omnidim_portal.views.csrf_failure"
SECURE_SSL_REDIRECT = not DEVELOPMENT
SECURE_HSTS_SECONDS = 31536000 if not DEVELOPMENT else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEVELOPMENT
SECURE_HSTS_PRELOAD = not DEVELOPMENT
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
# Enable only behind the supplied private gateway, which overwrites this header.
if os.environ.get("TRUST_PROXY") == "1":
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
DATA_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024
DATA_UPLOAD_MAX_NUMBER_FIELDS = 200
FILE_UPLOAD_MAX_MEMORY_SIZE = DATA_UPLOAD_MAX_MEMORY_SIZE
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage" if os.environ.get("VERCEL") == "1" else "whitenoise.storage.CompressedStaticFilesStorage"},
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
TIME_ZONE = "UTC"
LANGUAGE_CODE = "en-us"
PORTAL_READ_ONLY = os.environ.get("OMNIDIM_READ_ONLY") == "1"
PORTAL_HISTORY_DAYS = int(os.environ.get("HISTORY_RETENTION_DAYS", "30"))
if not 1 <= PORTAL_HISTORY_DAYS <= 365:
    raise ImproperlyConfigured("HISTORY_RETENTION_DAYS must be between 1 and 365.")
PORTAL_TRUST_PROXY = os.environ.get("TRUST_PROXY") == "1"
LOGGING = {
    "version": 1, "disable_existing_loggers": False,
    "formatters": {"json": {"()": "omnidim_portal.middleware.JsonFormatter"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "json"}},
    "root": {"handlers": ["console"], "level": "INFO"},
    "loggers": {"django.server": {"handlers": ["console"], "level": "WARNING", "propagate": False}},
}
