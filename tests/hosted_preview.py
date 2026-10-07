"""Disposable, loopback-only browser fixture. All upstream requests are fake."""
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path
from wsgiref.simple_server import make_server

from cryptography.fernet import Fernet

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))
with tempfile.TemporaryDirectory(prefix=".browser-fixture-", dir=root) as temporary:
    os.environ.pop("DATABASE_URL", None)
    os.environ.pop("VERCEL", None)
    os.environ.pop("OMNIDIM_READ_ONLY", None)
    os.environ["OMNIDIM_ENV"] = "development"
    os.environ["DJANGO_SETTINGS_MODULE"] = "omnidim_portal.settings"
    os.environ["DJANGO_SECRET_KEY"] = secrets.token_urlsafe(64)
    os.environ["OMNIDIM_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
    os.environ["ALLOWED_HOSTS"] = "localhost,127.0.0.1"
    os.environ["PORTAL_DB_PATH"] = str(Path(temporary) / "portal.sqlite3")
    os.environ["TRUST_PROXY"] = "0"
    import django
    django.setup()
    from django.conf import settings
    from django.contrib.auth import get_user_model
    from django.core.management import call_command
    from django.core.wsgi import get_wsgi_application
    from django.test.utils import override_settings

    from omnidim_portal import views
    from portal_core.models import Membership, Workspace
    call_command("migrate", verbosity=0)
    password = secrets.token_urlsafe(24)
    user = get_user_model().objects.create_user("browser-review", password=password)
    first = Workspace.objects.create(name="Design team", slug="design")
    first.set_api_key("synthetic-browser-key")
    first.save()
    second = Workspace.objects.create(name="Read-only team", slug="read-only")
    Membership.objects.create(user=user, workspace=first, role="admin")
    Membership.objects.create(user=user, workspace=second, role="viewer")
    views.execute_proxy_request = lambda *args, **kwargs: (200, True, {"notice": "Isolated browser fixture", "agents": []})
    settings.WHITENOISE_USE_FINDERS = True
    print(json.dumps({"ready": True, "username": user.username, "password": password}), flush=True)
    with override_settings(LOGGING={}):
        with make_server("127.0.0.1", int(os.environ.get("HOSTED_TEST_PORT", "8892")), get_wsgi_application()) as server:
            server.serve_forever()
