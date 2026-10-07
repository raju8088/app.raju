"""Staff-only recovery administration, with credentials and audit records protected."""

from django.contrib import admin

from portal_core.models import Membership, Operation, RequestHistory, SavedPayload, SecurityEvent, Workspace


def audit_admin_change(request, obj, action):
    workspace = obj if isinstance(obj, Workspace) else obj.workspace
    details = {"source": "django_admin", "record_id": obj.pk}
    if isinstance(obj, Membership):
        details.update(user_id=obj.user_id, role=obj.role, is_active=obj.is_active)
    SecurityEvent.objects.create(workspace=workspace, actor=request.user, event=f"admin.{obj._meta.model_name}.{action}", details=details)


class AuditedAdmin(admin.ModelAdmin):
    def log_addition(self, request, obj, message):
        result = super().log_addition(request, obj, message)
        audit_admin_change(request, obj, "created")
        return result

    def log_change(self, request, obj, message):
        result = super().log_change(request, obj, message)
        audit_admin_change(request, obj, "changed")
        return result

    def log_deletions(self, request, queryset):
        for obj in queryset:
            audit_admin_change(request, obj, "deleted")
        return super().log_deletions(request, queryset)


class MembershipInline(admin.TabularInline):
    model = Membership
    extra = 0
    autocomplete_fields = ["user"]


@admin.register(Workspace)
class WorkspaceAdmin(AuditedAdmin):
    list_display = ["name", "slug", "created_at"]
    search_fields = ["name", "slug"]
    readonly_fields = ["created_at", "base_url"]
    exclude = ["api_key_ciphertext"]
    inlines = [MembershipInline]

    def has_delete_permission(self, request, obj=None):
        # Workspace deletion requires a separate, auditable retention procedure.
        return False

    def save_formset(self, request, form, formset, change):
        if formset.model is not Membership:
            return super().save_formset(request, form, formset, change)
        instances = formset.save(commit=False)
        for obj in formset.deleted_objects:
            audit_admin_change(request, obj, "deleted")
            obj.delete()
        for obj in instances:
            action = "created" if obj._state.adding else "changed"
            obj.save()
            audit_admin_change(request, obj, action)
        formset.save_m2m()


@admin.register(Membership)
class MembershipAdmin(AuditedAdmin):
    list_display = ["user", "workspace", "role", "is_active"]
    list_filter = ["role", "is_active"]
    autocomplete_fields = ["user", "workspace"]
    search_fields = ["user__username", "workspace__name"]


class ReadOnlyAdmin(admin.ModelAdmin):
    actions = None

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(SecurityEvent)
class SecurityEventAdmin(ReadOnlyAdmin):
    list_display = ["created_at", "event", "workspace", "actor"]
    list_filter = ["event"]
    search_fields = ["workspace__slug", "actor__username", "event"]


@admin.register(Operation)
class OperationAdmin(ReadOnlyAdmin):
    list_display = ["created_at", "workspace", "user", "state", "method", "path", "status"]
    list_filter = ["state", "method"]
    search_fields = ["workspace__slug", "idempotency_key"]


@admin.register(RequestHistory)
class RequestHistoryAdmin(ReadOnlyAdmin):
    list_display = ["created_at", "workspace", "actor", "method", "path", "status"]
    list_filter = ["method", "ok"]


@admin.register(SavedPayload)
class SavedPayloadAdmin(ReadOnlyAdmin):
    list_display = ["name", "workspace", "owner", "endpoint_id", "updated_at"]
