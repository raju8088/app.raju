"""Durable records; every customer-owned row is explicitly workspace scoped."""

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from portal_core.secrets import decrypt_api_key, encrypt_api_key

DEFAULT_BASE_URL = "https://omnidim.io/api/v1"


class Workspace(models.Model):
    name = models.CharField(max_length=150)
    slug = models.SlugField(max_length=100, unique=True)
    api_key_ciphertext = models.TextField(blank=True, editable=False)
    base_url = models.URLField(default=DEFAULT_BASE_URL, max_length=500)
    retention_limit = models.PositiveIntegerField(default=5000, validators=[MinValueValidator(100), MaxValueValidator(100000)])
    actions_per_minute = models.PositiveIntegerField(default=30, validators=[MinValueValidator(1), MaxValueValidator(1000)])
    actions_per_day = models.PositiveIntegerField(default=1000, validators=[MinValueValidator(1), MaxValueValidator(100000)])
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name", "pk"]
        constraints = [
            models.CheckConstraint(condition=models.Q(retention_limit__gte=100, retention_limit__lte=100000), name="workspace_retention_range"),
            models.CheckConstraint(condition=models.Q(actions_per_minute__gte=1, actions_per_minute__lte=1000), name="workspace_minute_range"),
            models.CheckConstraint(condition=models.Q(actions_per_day__gte=1, actions_per_day__lte=100000), name="workspace_day_range"),
        ]

    def __str__(self) -> str:
        return self.name

    def clean(self) -> None:
        super().clean()
        if self.base_url.rstrip("/") != DEFAULT_BASE_URL:
            raise ValidationError({"base_url": "Use the approved OmniDimension API address."})
        self.base_url = DEFAULT_BASE_URL

    def set_api_key(self, value: str) -> None:
        """Encrypt in memory; the caller explicitly saves the workspace."""
        self.api_key_ciphertext = encrypt_api_key(value)

    def get_api_key(self) -> str:
        return decrypt_api_key(self.api_key_ciphertext)


class Membership(models.Model):
    class Role(models.TextChoices):
        VIEWER = "viewer", "Viewer"
        OPERATOR = "operator", "Operator"
        ADMIN = "admin", "Administrator"

    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE, related_name="memberships")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="workspace_memberships")
    role = models.CharField(max_length=10, choices=Role.choices, default=Role.VIEWER)
    is_active = models.BooleanField(default=True)
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["workspace", "user"], name="membership_workspace_user_uniq"),
            models.CheckConstraint(condition=models.Q(role__in=["viewer", "operator", "admin"]), name="membership_valid_role"),
        ]
        indexes = [models.Index(fields=["user", "is_active"], name="membership_user_active_idx")]

    def __str__(self) -> str:
        return f"{self.user_id} / {self.workspace}: {self.role}"

    @property
    def can_write(self) -> bool:
        return self.is_active and self.role in {self.Role.OPERATOR, self.Role.ADMIN}

    @property
    def can_admin(self) -> bool:
        return self.is_active and self.role == self.Role.ADMIN


class RequestHistory(models.Model):
    workspace = models.ForeignKey(Workspace, on_delete=models.PROTECT, related_name="request_history")
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="portal_request_history")
    endpoint_id = models.CharField(max_length=150, blank=True)
    method = models.CharField(max_length=10)
    path = models.CharField(max_length=2048)
    url = models.TextField(blank=True)
    status = models.PositiveSmallIntegerField(null=True)
    ok = models.BooleanField(default=False)
    duration_ms = models.PositiveIntegerField(default=0)
    request_json = models.JSONField(null=True, blank=True)
    response_json = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-pk"]
        indexes = [
            models.Index(fields=["workspace", "-created_at"], name="history_workspace_time_idx"),
            models.Index(fields=["workspace", "endpoint_id"], name="history_workspace_endpoint_idx"),
        ]


class SavedPayload(models.Model):
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE, related_name="saved_payloads")
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="portal_saved_payloads")
    endpoint_id = models.CharField(max_length=150)
    name = models.CharField(max_length=150)
    method = models.CharField(max_length=10)
    path = models.CharField(max_length=2048)
    query_json = models.JSONField(default=dict, blank=True)
    body_json = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at", "-pk"]
        constraints = [models.UniqueConstraint(fields=["workspace", "owner", "endpoint_id", "name"], name="payload_owner_name_uniq")]
        indexes = [models.Index(fields=["workspace", "owner", "endpoint_id"], name="payload_workspace_owner_idx")]


class AppendOnlyQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError("Security events are append-only.")

    def delete(self):
        raise ValidationError("Security events are append-only.")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValidationError("Security events are append-only.")

    def bulk_create(self, objs, batch_size=None, ignore_conflicts=False, update_conflicts=False, update_fields=None, unique_fields=None):
        if update_conflicts or ignore_conflicts:
            raise ValidationError("Security event conflicts must not be ignored or overwritten.")
        return super().bulk_create(objs, batch_size=batch_size)


class SecurityEvent(models.Model):
    workspace = models.ForeignKey(Workspace, on_delete=models.PROTECT, null=True, blank=True, related_name="security_events")
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True, related_name="portal_security_events")
    event = models.CharField(max_length=100)
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = AppendOnlyQuerySet.as_manager()

    class Meta:
        ordering = ["-created_at", "-pk"]
        indexes = [models.Index(fields=["workspace", "-created_at"], name="audit_workspace_time_idx")]
        default_permissions = ("add", "view")

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError("Security events are append-only.")
        kwargs["force_insert"] = True
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Security events are append-only.")


class Confirmation(models.Model):
    token_hash = models.CharField(max_length=64, unique=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="portal_confirmations")
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE, related_name="confirmations")
    method = models.CharField(max_length=10)
    path = models.CharField(max_length=2048)
    signature = models.CharField(max_length=64)
    expires_at = models.DateTimeField(db_index=True)
    consumed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class Operation(models.Model):
    class State(models.TextChoices):
        PENDING = "pending", "Pending"
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"
        UNKNOWN = "unknown", "Outcome unknown"

    workspace = models.ForeignKey(Workspace, on_delete=models.PROTECT, related_name="operations")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="portal_operations")
    idempotency_key = models.CharField(max_length=128)
    signature = models.CharField(max_length=64)
    state = models.CharField(max_length=12, choices=State.choices, default=State.PENDING)
    method = models.CharField(max_length=10, blank=True)
    path = models.CharField(max_length=2048, blank=True)
    endpoint_id = models.CharField(max_length=150, blank=True)
    response = models.JSONField(null=True, blank=True)
    status = models.PositiveSmallIntegerField(null=True, blank=True)
    error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["workspace", "idempotency_key"], name="operation_workspace_key_uniq"),
            models.CheckConstraint(condition=models.Q(state__in=["pending", "succeeded", "failed", "unknown"]), name="operation_valid_state"),
        ]
        indexes = [models.Index(fields=["workspace", "state", "created_at"], name="operation_state_time_idx")]


class RateWindow(models.Model):
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE, related_name="rate_windows")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="portal_rate_windows")
    scope = models.CharField(max_length=64)
    window = models.BigIntegerField()
    count = models.PositiveIntegerField(default=0)
    expires_at = models.DateTimeField(db_index=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["workspace", "user", "scope", "window"], name="rate_window_scope_uniq")]


class LoginThrottle(models.Model):
    """Shared login attempt counters; keys are hashes, never raw identifiers."""

    key_hash = models.CharField(max_length=64)
    window = models.BigIntegerField()
    count = models.PositiveIntegerField(default=0)
    expires_at = models.DateTimeField(db_index=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["key_hash", "window"], name="login_throttle_window_uniq")]
