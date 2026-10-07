"""Check production defaults with disposable secrets; never contacts a real database."""
import os
import secrets
import sys
from pathlib import Path

from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.update(
    OMNIDIM_ENV="production",
    DJANGO_SECRET_KEY=secrets.token_urlsafe(64),
    OMNIDIM_ENCRYPTION_KEY=Fernet.generate_key().decode(),
    ALLOWED_HOSTS="test.example.com",
    CSRF_TRUSTED_ORIGINS="https://test.example.com",
    DATABASE_URL="postgresql://test:fake-test-password@127.0.0.1:6543/test",
    DATABASE_SSLMODE="require",
)
os.environ["DJANGO_SETTINGS_MODULE"] = "omnidim_portal.settings"
import django  # noqa: E402

django.setup()
from django.core.management import call_command  # noqa: E402

call_command("check", deploy=True, fail_level="WARNING")
