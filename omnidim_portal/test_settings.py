"""Isolated test configuration; never used by the production entrypoint."""
import os
import tempfile
from pathlib import Path

os.environ["OMNIDIM_ENV"] = "development"
os.environ["DJANGO_SECRET_KEY"] = "test-only-django-secret-" * 4
os.environ["OMNIDIM_ENCRYPTION_KEY"] = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
os.environ["ALLOWED_HOSTS"] = "testserver,localhost,127.0.0.1"
from .settings import *  # noqa: E402,F403

DEBUG = False
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
if os.environ.get("TEST_DATABASE_URL"):
    # CI also tests real PostgreSQL locking and constraints using production configuration.
    parsed_test = urlsplit(os.environ["TEST_DATABASE_URL"])  # noqa: F405
    DATABASES = {"default": {
        "ENGINE": "django.db.backends.postgresql", "NAME": parsed_test.path.lstrip("/"),
        "USER": parsed_test.username, "PASSWORD": parsed_test.password,
        "HOST": parsed_test.hostname, "PORT": parsed_test.port or 5432,
    }}
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
STATIC_ROOT = Path(tempfile.gettempdir()) / "omni-test-static"
MIDDLEWARE = [item for item in MIDDLEWARE if "WhiteNoise" not in item]  # noqa: F405
