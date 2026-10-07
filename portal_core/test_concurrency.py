"""Real concurrent request checks; SQLite cannot verify PostgreSQL row locking."""

import json
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from threading import Barrier, Event
from unittest import skipUnless
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import connection, connections
from django.test import Client, TransactionTestCase

from portal_core.models import Membership, Operation, Workspace


@skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL transactions and row locks; CI provides PostgreSQL.")
class ConcurrentOperationTests(TransactionTestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="concurrent", password="test-only-password")
        self.workspace = Workspace.objects.create(name="Concurrent test", slug="concurrent-test")
        self.workspace.set_api_key("test-only-concurrency-credential")
        self.workspace.save()
        Membership.objects.create(user=self.user, workspace=self.workspace, role=Membership.Role.ADMIN)
        self.clients = [Client(), Client()]
        for client in self.clients:
            client.force_login(self.user)
            client.get("/api/session")
        self.payload = json.dumps({"method": "POST", "path": "/sessions/create", "body": {"agent_id": 1}})

    def submit(self, client, key, barrier=None):
        # Django connections are thread-local; close both before and after each
        # worker to guarantee independent transactions and release test DB locks.
        connections.close_all()
        try:
            if barrier is not None:
                barrier.wait(timeout=10)
            response = client.post("/api/run", self.payload, content_type="application/json",
                                   HTTP_X_WORKSPACE_ID=str(self.workspace.pk), HTTP_IDEMPOTENCY_KEY=key)
            return response.status_code, response.json()
        finally:
            connections.close_all()

    def test_simultaneous_duplicate_executes_upstream_once(self):
        barrier, release_upstream = Barrier(2), Event()

        def upstream_response(*args, **kwargs):
            if not release_upstream.wait(timeout=15):
                raise TimeoutError("Test did not release upstream")
            return 200, True, {"id": "test-session"}

        key = "concurrency-same-request-0001"
        with patch("omnidim_portal.views.execute_proxy_request", side_effect=upstream_response) as upstream:
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(self.submit, client, key, barrier) for client in self.clients]
                try:
                    completed, _ = wait(futures, timeout=10, return_when=FIRST_COMPLETED)
                    self.assertTrue(completed, "A duplicate request must return while the first upstream call is pending")
                    status, body = next(iter(completed)).result()
                    self.assertEqual(status, 409)
                    self.assertEqual(body["code"], "operation_pending")
                finally:
                    release_upstream.set()
                results = [future.result(timeout=10) for future in futures]
            self.assertEqual(sorted(status for status, _ in results), [200, 409])
            self.assertEqual(upstream.call_count, 1)
            self.assertEqual(Operation.objects.filter(workspace=self.workspace).count(), 1)
            self.assertEqual(Operation.objects.get(workspace=self.workspace).state, Operation.State.SUCCEEDED)
            replay = self.clients[0].post("/api/run", self.payload, content_type="application/json",
                                          HTTP_X_WORKSPACE_ID=str(self.workspace.pk), HTTP_IDEMPOTENCY_KEY=key)
            self.assertEqual(replay.status_code, 200)
            self.assertTrue(replay.json()["replayed"])
            self.assertEqual(upstream.call_count, 1)

    def test_simultaneous_distinct_requests_cannot_exceed_workspace_budget(self):
        self.workspace.actions_per_minute = 1
        self.workspace.save(update_fields=["actions_per_minute"])
        barrier = Barrier(2)
        with patch("omnidim_portal.views.execute_proxy_request", return_value=(200, True, {"id": "test-session"})) as upstream:
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(self.submit, client, f"concurrency-budget-key-{index:04}", barrier)
                           for index, client in enumerate(self.clients)]
                results = [future.result(timeout=15) for future in futures]
            self.assertEqual(sorted(status for status, _ in results), [200, 429])
            self.assertEqual(upstream.call_count, 1)
            self.assertEqual(Operation.objects.filter(workspace=self.workspace).count(), 1)
