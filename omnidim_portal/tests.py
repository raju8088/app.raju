import json
from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import DatabaseError
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from portal_core.models import (
    Confirmation,
    LoginThrottle,
    Membership,
    Operation,
    RateWindow,
    RequestHistory,
    SavedPayload,
    Workspace,
)


class HostedApiTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin", password="test-secret")
        self.other = get_user_model().objects.create_user("other", password="test-secret")
        self.workspace = Workspace.objects.create(name="One", slug="one")
        self.workspace.set_api_key("fake-test-key")
        self.workspace.save()
        self.second = Workspace.objects.create(name="Two", slug="two")
        self.membership = Membership.objects.create(user=self.user, workspace=self.workspace, role="admin")
        Membership.objects.create(user=self.other, workspace=self.second, role="admin")
        self.client.force_login(self.user)
        self.client.get("/api/session")
        self.headers = {"HTTP_X_WORKSPACE_ID": str(self.workspace.pk)}

    def send(self, route, data=None, method="post", **headers):
        return getattr(self.client, method)("/api/" + route, data=json.dumps(data or {}), content_type="application/json", **self.headers, **headers)

    def test_authentication_and_csrf(self):
        self.assertEqual(Client().get("/api/session").status_code, 401)
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        self.assertEqual(client.post("/api/logout", "{}", content_type="application/json").status_code, 403)
        token = client.get("/api/session").json()["csrfToken"]
        self.assertEqual(client.post("/api/logout", "{}", content_type="application/json", HTTP_X_CSRF_TOKEN=token).status_code, 200)

    def test_workspace_guard_and_switch(self):
        self.assertEqual(self.client.get("/api/settings").status_code, 409)
        self.assertEqual(self.send("workspace", {"workspaceId": self.second.pk}).status_code, 403)
        self.assertEqual(self.client.get("/api/settings", **self.headers).status_code, 200)
        self.membership.is_active = False
        self.membership.save()
        self.assertEqual(self.client.get("/api/settings", **self.headers).status_code, 403)

    @patch("omnidim_portal.views.execute_proxy_request", return_value=(200, True, {"agents": []}))
    def test_viewer_can_read_cannot_modify(self, upstream):
        self.membership.role = "viewer"
        self.membership.save()
        self.assertEqual(self.send("run", {"method": "GET", "path": "/agents"}).status_code, 200)
        self.assertEqual(self.send("run", {"method": "POST", "path": "/sessions/create"}).status_code, 403)
        self.assertEqual(self.send("settings", {"apiKey": "another"}, "put").status_code, 403)
        self.assertEqual(upstream.call_count, 1)

    @patch("omnidim_portal.views.execute_proxy_request", return_value=(200, True, {"id": 22}))
    def test_duplicate_mutation_never_repeats(self, upstream):
        data = {"method": "POST", "path": "/sessions/create", "body": {"agent_id": 1}}
        headers = {"HTTP_IDEMPOTENCY_KEY": "test-idempotency-key-0001"}
        self.assertEqual(self.send("run", data, **headers).status_code, 200)
        response = self.send("run", data, **headers)
        self.assertTrue(response.json()["replayed"])
        self.assertEqual(upstream.call_count, 1)
        self.assertEqual(Operation.objects.count(), 1)
        data["body"] = {"agent_id": 2}
        self.assertEqual(self.send("run", data, **headers).status_code, 409)

    @patch("omnidim_portal.views.execute_proxy_request", return_value=(None, False, {"error": "timeout"}))
    def test_uncertain_mutation_blocks_retry(self, upstream):
        data = {"method": "POST", "path": "/sessions/create"}
        headers = {"HTTP_IDEMPOTENCY_KEY": "test-idempotency-key-0002"}
        self.assertEqual(self.send("run", data, **headers).status_code, 502)
        response = self.send("run", data, **headers)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["code"], "operation_uncertain")
        self.assertEqual(upstream.call_count, 1)

    @patch("omnidim_portal.views.execute_proxy_request", return_value=(200, True, {}))
    def test_confirmation_single_use_request_binding(self, upstream):
        from omnidim_ui.endpoints import ENDPOINTS
        endpoint = next(item for item in ENDPOINTS if item["danger"] and "{" not in item["path"])
        data = {"method": endpoint["method"], "path": endpoint["path"], "body": {}}
        headers = {"HTTP_IDEMPOTENCY_KEY": "danger-idempotency-key-0001"}
        self.assertEqual(self.send("run", data, **headers).status_code, 403)
        data["confirmToken"] = self.send("preflight", data).json()["confirmToken"]
        self.assertEqual(upstream.call_count, 0)
        self.assertEqual(self.send("run", data, **headers).status_code, 200)
        self.assertEqual(self.send("run", data, **headers).status_code, 200)
        self.assertEqual(self.send("run", data, HTTP_IDEMPOTENCY_KEY="danger-idempotency-key-0002").status_code, 403)
        self.assertEqual(upstream.call_count, 1)

    def test_settings_validation_and_encryption(self):
        self.assertEqual(self.send("settings", {"apiKey": "new-fake-key", "retentionLimit": 100}, "put").status_code, 200)
        self.workspace.refresh_from_db()
        self.assertNotIn("new-fake-key", self.workspace.api_key_ciphertext)
        self.assertEqual(self.workspace.get_api_key(), "new-fake-key")
        for body in ({"retentionLimit": -1}, {"retentionLimit": True}, {"baseUrl": "https://evil.example/api/v1"}):
            self.assertEqual(self.send("settings", body, "put").status_code, 400)
        self.assertEqual(self.send("settings/api-key", method="delete").status_code, 200)

    def test_tenant_history_and_private_saved_requests(self):
        RequestHistory.objects.create(workspace=self.second, actor=self.other, method="GET", path="/secret")
        self.assertEqual(self.client.get("/api/history", **self.headers).json()["total"], 0)
        data = {"name": "My request", "method": "GET", "path": "/agents", "query": {"pagesize": 10}}
        self.assertEqual(self.send("saved-payloads", data).status_code, 200)
        record = SavedPayload.objects.get()
        self.assertEqual(record.workspace_id, self.workspace.pk)
        self.assertEqual(self.send(f"saved-payloads/{record.pk}", method="delete").status_code, 200)

    @patch("omnidim_portal.views.execute_proxy_request", return_value=(200, True, {}))
    def test_workspace_budget_and_missing_idempotency(self, upstream):
        self.workspace.actions_per_minute = 1
        self.workspace.save()
        self.assertEqual(self.send("run", {"method": "POST", "path": "/sessions/create"}).status_code, 400)
        self.assertEqual(self.send("run", {"method": "GET", "path": "/agents"}).status_code, 200)
        self.assertEqual(self.send("run", {"method": "GET", "path": "/agents"}).status_code, 429)
        self.assertEqual(upstream.call_count, 1)

    @override_settings(PORTAL_READ_ONLY=True)
    def test_global_read_only(self):
        self.assertEqual(self.send("run", {"method": "POST", "path": "/sessions/create"}).status_code, 403)

    def test_health_login_headers_and_invalid_input(self):
        self.assertEqual(self.client.get("/health/ready").status_code, 200)
        self.assertEqual(self.client.get("/health/live").status_code, 200)
        page = Client().get("/login/")
        self.assertContains(page, "Your workspace awaits")
        self.assertIn("Content-Security-Policy", page)
        self.assertEqual(self.send("unknown").status_code, 404)
        self.assertEqual(self.send("run", {"path": "/not-registered"}).status_code, 400)

    def test_login_success_and_shared_throttle(self):
        client = Client()
        self.assertEqual(client.post("/login/", {"username": "admin", "password": "test-secret"}).status_code, 302)
        self.assertEqual(client.get("/api/session").status_code, 200)
        client = Client()
        for _ in range(10):
            self.assertEqual(client.post("/login/", {"username": "no-such-account", "password": "incorrect"}).status_code, 200)
        self.assertEqual(client.post("/admin/login/", {"username": "no-such-account", "password": "incorrect"}).status_code, 429)
        self.assertTrue(LoginThrottle.objects.exists())

    def test_workspace_switch_is_membership_scoped(self):
        Membership.objects.create(user=self.user, workspace=self.second, role="viewer")
        for value in (True, "bad", -1):
            self.assertEqual(self.send("workspace", {"workspaceId": value}).status_code, 400)
        self.assertEqual(self.send("workspace", {"workspaceId": self.second.pk}).status_code, 200)
        self.assertEqual(self.client.get("/api/settings", **self.headers).status_code, 409)
        session = self.client.get("/api/session").json()
        self.assertEqual(session["workspace"]["id"], self.second.pk)
        self.assertEqual(session["role"], "viewer")

    @patch("omnidim_portal.views.execute_proxy_request", return_value=(200, True, {}))
    def test_pending_and_expired_operations_never_reexecute(self, upstream):
        data = {"method": "POST", "path": "/sessions/create"}
        key = "durable-result-expired-key-001"
        self.send("run", data, HTTP_IDEMPOTENCY_KEY=key)
        operation = Operation.objects.get()
        operation.state = "pending"
        operation.save()
        self.assertEqual(self.send("run", data, HTTP_IDEMPOTENCY_KEY=key).json()["code"], "operation_pending")
        operation.state, operation.response = "succeeded", None
        operation.save()
        self.assertEqual(self.send("run", data, HTTP_IDEMPOTENCY_KEY=key).json()["code"], "response_expired")
        self.assertEqual(upstream.call_count, 1)
        self.assertEqual(self.client.get(f"/api/operations/{operation.pk}", **self.headers).status_code, 200)
        self.assertEqual(self.client.get("/api/operations/999999", **self.headers).status_code, 404)

    @patch("omnidim_portal.views.execute_proxy_request", return_value=(200, True, {}))
    def test_known_success_survives_history_failure(self, upstream):
        with patch("omnidim_portal.views.RequestHistory.objects.create", side_effect=DatabaseError("synthetic failure")):
            response = self.send("run", {"method": "POST", "path": "/sessions/create"}, HTTP_IDEMPOTENCY_KEY="history-storage-failure-key-01")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])
        self.assertIn("warning", response.json())
        self.assertEqual(Operation.objects.get().state, "succeeded")

    @patch("omnidim_portal.views.execute_proxy_request", return_value=(200, True, {}))
    def test_known_result_persistence_failure_blocks_repeat(self, upstream):
        data = {"method": "POST", "path": "/sessions/create"}
        headers = {"HTTP_IDEMPOTENCY_KEY": "operation-storage-failure-key-01"}
        with patch("omnidim_portal.views.event", side_effect=[None, DatabaseError("synthetic failure")]):
            response = self.send("run", data, **headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn("warning", response.json())
        self.assertEqual(self.send("run", data, **headers).json()["code"], "operation_pending")
        self.assertEqual(upstream.call_count, 1)

    @patch("omnidim_portal.views.execute_proxy_request", side_effect=TimeoutError("synthetic timeout"))
    def test_transport_exception_records_unknown_outcome(self, upstream):
        response = self.send("run", {"method": "POST", "path": "/sessions/create"}, HTTP_IDEMPOTENCY_KEY="transport-exception-key-0001")
        self.assertEqual(response.status_code, 502)
        self.assertEqual(Operation.objects.get().state, "unknown")

    def test_admin_endpoint_requires_admin_role(self):
        self.membership.role = "operator"
        self.membership.save()
        self.assertEqual(self.send("preflight", {"method": "GET", "path": "/reseller/organizations"}).status_code, 403)

    def test_missing_credential_and_history_clear(self):
        self.workspace.set_api_key("")
        self.workspace.save()
        self.assertEqual(self.send("run", {"method": "GET", "path": "/agents"}).json()["code"], "connection_missing")
        RequestHistory.objects.create(workspace=self.workspace, method="GET", path="/agents")
        self.assertEqual(self.send("history", method="delete").status_code, 200)
        self.assertFalse(RequestHistory.objects.exists())
        self.assertEqual(self.client.post("/api/session").status_code, 405)

    def test_saved_request_validation_and_privacy(self):
        record = SavedPayload.objects.create(workspace=self.second, owner=self.other, name="Private", endpoint_id="get-agents", method="GET", path="/agents")
        self.assertEqual(self.send(f"saved-payloads/{record.pk}", method="delete").status_code, 404)
        self.assertEqual(self.send("saved-payloads", {"name": "", "method": "GET", "path": "/agents"}).status_code, 400)
        self.assertEqual(self.client.get("/api/saved-payloads", **self.headers).json()["records"], [])

    def test_invalid_credentials_retention_and_readiness_failure(self):
        for key in (None, 25, ""):
            self.assertEqual(self.send("settings", {"apiKey": key}, "put").status_code, 400)
        self.assertEqual(self.send("settings", {"baseUrl": "https://omnidim.io/api/v1/agents"}, "put").status_code, 400)
        with patch("omnidim_portal.views.Membership.objects.exists", side_effect=DatabaseError("synthetic outage")):
            self.assertEqual(self.client.get("/health/ready").status_code, 503)

    def test_maintenance_preserves_action_identity(self):
        stale = timezone.now() - timedelta(days=40)
        operation = Operation.objects.create(workspace=self.workspace, user=self.user, idempotency_key="maintenance-tombstone", signature="0" * 64, response={"ok": True})
        Operation.objects.filter(pk=operation.pk).update(created_at=stale)
        history = RequestHistory.objects.create(workspace=self.workspace, method="GET", path="/agents")
        RequestHistory.objects.filter(pk=history.pk).update(created_at=stale)
        Confirmation.objects.create(user=self.user, workspace=self.workspace, token_hash="0" * 64, method="DELETE", path="/agents/1", signature="0" * 64, expires_at=stale)
        RateWindow.objects.create(user=self.user, workspace=self.workspace, scope="test", window=1, expires_at=stale)
        call_command("portal_maintenance", stdout=StringIO())
        operation.refresh_from_db()
        self.assertEqual(operation.state, "unknown")
        self.assertIsNone(operation.response)
        self.assertFalse(RequestHistory.objects.exists())
        self.assertFalse(Confirmation.objects.exists())
        self.assertFalse(RateWindow.objects.exists())
