"""Identity and persistence tests always use Django's isolated test database."""

from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import ImproperlyConfigured, PermissionDenied, ValidationError
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError, transaction
from django.test import RequestFactory, TestCase
from django.utils import timezone

from portal_core.auth import get_membership
from portal_core.models import Confirmation, Membership, Operation, RateWindow, SavedPayload, SecurityEvent, Workspace
from portal_core.secrets import decrypt_api_key, encrypt_api_key, rotate_api_key


class IdentityTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(username="alice", password="test-password-alice")
        cls.other = get_user_model().objects.create_user(username="bob", password="test-password-bob")
        cls.workspace = Workspace.objects.create(name="Team A", slug="team-a")
        cls.other_workspace = Workspace.objects.create(name="Team B", slug="team-b")
        cls.membership = Membership.objects.create(workspace=cls.workspace, user=cls.user, role=Membership.Role.ADMIN)
        Membership.objects.create(workspace=cls.other_workspace, user=cls.other, role=Membership.Role.ADMIN)

    def request(self, user=None, workspace_id=None):
        request = RequestFactory().get("/")
        request.user = user if user is not None else self.user
        request.session = {}
        if workspace_id is not None:
            request.session["active_workspace_id"] = workspace_id
        return request

    def test_unique_membership_selects_workspace(self):
        request = self.request()
        membership = get_membership(request)
        self.assertEqual(membership.pk, self.membership.pk)
        self.assertEqual(request.session["active_workspace_id"], self.workspace.pk)

    def test_cross_workspace_selection_denied(self):
        with self.assertRaises(PermissionDenied):
            get_membership(self.request(workspace_id=self.other_workspace.pk))

    def test_ambiguous_membership_requires_selection(self):
        Membership.objects.create(workspace=self.other_workspace, user=self.user)
        with self.assertRaises(PermissionDenied):
            get_membership(self.request())
        self.assertEqual(get_membership(self.request(workspace_id=self.workspace.pk)).workspace_id, self.workspace.pk)

    def test_anonymous_and_inactive_users_are_denied(self):
        with self.assertRaises(PermissionDenied):
            get_membership(self.request(user=AnonymousUser()))
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        with self.assertRaises(PermissionDenied):
            get_membership(self.request())

    def test_revocation_and_role_changes_take_effect(self):
        request = self.request(workspace_id=self.workspace.pk)
        self.assertTrue(get_membership(request, [Membership.Role.ADMIN]).can_admin)
        Membership.objects.filter(pk=self.membership.pk).update(role=Membership.Role.VIEWER)
        with self.assertRaises(PermissionDenied):
            get_membership(request, [Membership.Role.ADMIN, Membership.Role.OPERATOR])
        self.assertFalse(get_membership(request).can_write)
        Membership.objects.filter(pk=self.membership.pk).update(is_active=False)
        with self.assertRaises(PermissionDenied):
            get_membership(request)

    def test_superuser_needs_workspace_membership(self):
        self.user.is_superuser = True
        self.user.save(update_fields=["is_superuser"])
        with self.assertRaises(PermissionDenied):
            get_membership(self.request(workspace_id=self.other_workspace.pk))

    def test_malformed_workspace_selection_denied(self):
        for value in ("garbage", True, [], {}, 0, -1, "999999999999999999999999999999"):
            with self.subTest(value=value), self.assertRaises(PermissionDenied):
                get_membership(self.request(workspace_id=value))

    def test_membership_unique_and_roles_constrained(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            Membership.objects.create(user=self.user, workspace=self.workspace)
        with self.assertRaises(IntegrityError), transaction.atomic():
            Membership.objects.create(user=self.user, workspace=self.other_workspace, role="owner")

    def test_saved_payloads_are_owner_and_workspace_scoped(self):
        payload = {"endpoint_id": "agents.create", "name": "Example", "method": "POST", "path": "/agents", "body_json": {"large": "x" * 250000}}
        first = SavedPayload.objects.create(workspace=self.workspace, owner=self.user, **payload)
        SavedPayload.objects.create(workspace=self.other_workspace, owner=self.other, **payload)
        self.assertEqual(SavedPayload.objects.filter(workspace=self.workspace, owner=self.user).count(), 1)
        self.assertEqual(SavedPayload.objects.get(pk=first.pk).body_json, payload["body_json"])
        with self.assertRaises(IntegrityError), transaction.atomic():
            SavedPayload.objects.create(workspace=self.workspace, owner=self.user, **payload)

    def test_operation_key_unique_per_workspace(self):
        Operation.objects.create(workspace=self.workspace, user=self.user, idempotency_key="one-request", signature="a" * 64)
        Operation.objects.create(workspace=self.other_workspace, user=self.other, idempotency_key="one-request", signature="b" * 64)
        with self.assertRaises(IntegrityError), transaction.atomic():
            Operation.objects.create(workspace=self.workspace, user=self.user, idempotency_key="one-request", signature="c" * 64)

    def test_confirmation_and_rate_window_are_durable_and_scoped(self):
        expiry = timezone.now() + timedelta(minutes=1)
        Confirmation.objects.create(user=self.user, workspace=self.workspace, token_hash="a" * 64, signature="b" * 64, method="POST", path="/call", expires_at=expiry)
        self.assertFalse(Confirmation.objects.filter(user=self.other, workspace=self.other_workspace).exists())
        RateWindow.objects.create(user=self.user, workspace=self.workspace, scope="minute", window=1, count=1, expires_at=expiry)
        with self.assertRaises(IntegrityError), transaction.atomic():
            RateWindow.objects.create(user=self.user, workspace=self.workspace, scope="minute", window=1, count=2, expires_at=expiry)


class EncryptionTests(TestCase):
    def test_requires_explicit_encryption_key(self):
        with patch.dict("os.environ", {"OMNIDIM_ENCRYPTION_KEY": ""}):
            with self.assertRaises(ImproperlyConfigured):
                encrypt_api_key("test-only-upstream-credential")
            with self.assertRaises(ImproperlyConfigured):
                decrypt_api_key("")

    def test_credentials_are_encrypted_at_rest_and_workspace_specific(self):
        with patch.dict("os.environ", {"OMNIDIM_ENCRYPTION_KEY": Fernet.generate_key().decode()}):
            first = Workspace.objects.create(name="First", slug="first")
            second = Workspace.objects.create(name="Second", slug="second")
            first.set_api_key("test-only-first-secret")
            second.set_api_key("test-only-second-secret")
            first.save()
            second.save()
            first.refresh_from_db()
            self.assertNotIn("test-only-first-secret", first.api_key_ciphertext)
            self.assertEqual(first.get_api_key(), "test-only-first-secret")
            self.assertEqual(second.get_api_key(), "test-only-second-secret")
            self.assertNotEqual(first.api_key_ciphertext, second.api_key_ciphertext)

    def test_wrong_or_invalid_key_fails_closed(self):
        with patch.dict("os.environ", {"OMNIDIM_ENCRYPTION_KEY": Fernet.generate_key().decode()}):
            ciphertext = encrypt_api_key("test-only-secret")
        for key in (Fernet.generate_key().decode(), "invalid"):
            with self.subTest(key_format="valid" if key != "invalid" else "invalid"):
                with patch.dict("os.environ", {"OMNIDIM_ENCRYPTION_KEY": key}), self.assertRaises(ImproperlyConfigured):
                    decrypt_api_key(ciphertext)

    def test_previous_key_can_be_rotated_without_exposing_plaintext(self):
        old_key, new_key = Fernet.generate_key().decode(), Fernet.generate_key().decode()
        with patch.dict("os.environ", {"OMNIDIM_ENCRYPTION_KEY": old_key, "OMNIDIM_ENCRYPTION_PREVIOUS_KEYS": ""}):
            ciphertext = encrypt_api_key("test-only-secret")
        with patch.dict("os.environ", {"OMNIDIM_ENCRYPTION_KEY": new_key, "OMNIDIM_ENCRYPTION_PREVIOUS_KEYS": old_key}):
            self.assertEqual(decrypt_api_key(ciphertext), "test-only-secret")
            rotated = rotate_api_key(ciphertext)
        with patch.dict("os.environ", {"OMNIDIM_ENCRYPTION_KEY": new_key, "OMNIDIM_ENCRYPTION_PREVIOUS_KEYS": ""}):
            self.assertEqual(decrypt_api_key(rotated), "test-only-secret")
            with self.assertRaises(ImproperlyConfigured):
                decrypt_api_key(ciphertext)


class AuditAndProvisioningTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = get_user_model().objects.create_user(username="owner")
        cls.workspace = Workspace.objects.create(name="Team", slug="team")

    def test_audit_records_cannot_be_rewritten_or_deleted(self):
        event = SecurityEvent.objects.create(actor=self.owner, workspace=self.workspace, event="login.succeeded")
        event.event = "replacement"
        for change in (lambda: event.save(), lambda: event.delete(), lambda: SecurityEvent.objects.filter(pk=event.pk).delete(), lambda: SecurityEvent.objects.filter(pk=event.pk).update(event="replacement")):
            with self.assertRaises(ValidationError):
                change()
        self.assertEqual(SecurityEvent.objects.get(pk=event.pk).event, "login.succeeded")
        with self.assertRaises(IntegrityError), transaction.atomic():
            SecurityEvent(pk=event.pk, event="replacement").save()
        with self.assertRaises(ValidationError):
            SecurityEvent.objects.bulk_create([SecurityEvent(event="ignored")], ignore_conflicts=True)

    def test_workspace_command_creates_admin_and_audit_atomically(self):
        call_command("create_workspace", name="New workspace", slug="new-workspace", owner="owner", stdout=StringIO())
        workspace = Workspace.objects.get(slug="new-workspace")
        self.assertEqual(Membership.objects.get(workspace=workspace, user=self.owner).role, Membership.Role.ADMIN)
        self.assertEqual(SecurityEvent.objects.get(workspace=workspace).event, "workspace.created")
        self.assertEqual(workspace.api_key_ciphertext, "")
        with self.assertRaises(CommandError):
            call_command("create_workspace", name="Duplicate", slug="new-workspace", owner="owner", stdout=StringIO())
        self.assertEqual(Workspace.objects.filter(slug="new-workspace").count(), 1)

    def test_workspace_command_rejects_nonexistent_and_inactive_owners(self):
        for owner in ("missing", "owner"):
            self.owner.is_active = False
            self.owner.save(update_fields=["is_active"])
            with self.assertRaises(CommandError):
                call_command("create_workspace", name="Not created", slug="not-created", owner=owner, stdout=StringIO())
        self.assertFalse(Workspace.objects.filter(slug="not-created").exists())

    def test_workspace_validation_rejects_unapproved_upstream(self):
        self.workspace.base_url = "https://attacker.example/api/v1"
        with self.assertRaises(ValidationError):
            self.workspace.full_clean()
        self.workspace.base_url = "https://omnidim.io/api/v1/"
        self.workspace.full_clean()
        self.assertEqual(self.workspace.base_url, "https://omnidim.io/api/v1")

    def test_admin_membership_changes_are_audited(self):
        self.owner.is_staff = True
        self.owner.is_superuser = True
        self.owner.save(update_fields=["is_staff", "is_superuser"])
        self.client.force_login(self.owner)
        data = {"workspace": self.workspace.pk, "user": self.owner.pk, "role": "viewer", "is_active": "on"}
        self.assertEqual(self.client.post("/admin/portal_core/membership/add/", data).status_code, 302)
        member = Membership.objects.get(workspace=self.workspace, user=self.owner)
        added = SecurityEvent.objects.get(event="admin.membership.created")
        self.assertEqual(added.workspace, self.workspace)
        self.assertEqual(added.actor, self.owner)
        self.assertEqual(added.details["role"], "viewer")
        data["role"] = "operator"
        self.assertEqual(self.client.post(f"/admin/portal_core/membership/{member.pk}/change/", data).status_code, 302)
        self.assertEqual(SecurityEvent.objects.get(event="admin.membership.changed").details["role"], "operator")
        self.assertEqual(self.client.post(f"/admin/portal_core/membership/{member.pk}/delete/", {"post": "yes"}).status_code, 302)
        self.assertTrue(SecurityEvent.objects.filter(event="admin.membership.deleted", workspace=self.workspace).exists())
        self.assertFalse(Membership.objects.filter(pk=member.pk).exists())

    def test_admin_workspace_deletion_is_disabled(self):
        self.owner.is_staff = True
        self.owner.is_superuser = True
        self.owner.save(update_fields=["is_staff", "is_superuser"])
        self.client.force_login(self.owner)
        response = self.client.post(f"/admin/portal_core/workspace/{self.workspace.pk}/delete/", {"post": "yes"})
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Workspace.objects.filter(pk=self.workspace.pk).exists())

    def test_rotation_command_is_atomic_when_any_credential_is_invalid(self):
        old_key, new_key = Fernet.generate_key().decode(), Fernet.generate_key().decode()
        with patch.dict("os.environ", {"OMNIDIM_ENCRYPTION_KEY": old_key, "OMNIDIM_ENCRYPTION_PREVIOUS_KEYS": ""}):
            self.workspace.set_api_key("test-only-credential")
            self.workspace.save()
        original_ciphertext = self.workspace.api_key_ciphertext
        Workspace.objects.create(name="Z invalid", slug="invalid", api_key_ciphertext="tampered-ciphertext")
        with patch.dict("os.environ", {"OMNIDIM_ENCRYPTION_KEY": new_key, "OMNIDIM_ENCRYPTION_PREVIOUS_KEYS": old_key}):
            with self.assertRaises(ImproperlyConfigured):
                call_command("rotate_workspace_keys", stdout=StringIO())
        self.workspace.refresh_from_db()
        self.assertEqual(self.workspace.api_key_ciphertext, original_ciphertext)
        self.assertFalse(SecurityEvent.objects.filter(event="workspace.credential_rotated").exists())
