"""Authenticated workspace API. No customer credential falls back to a process global."""
import hashlib
import json
import logging
import math
import re
import secrets
import time
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, transaction
from django.db.models import F, Q, Sum
from django.http import HttpResponse, JsonResponse
from django.middleware.csrf import get_token
from django.utils import timezone

from omnidim_ui.endpoints import ENDPOINTS, GROUPS, is_dangerous_operation
from omnidim_ui.handlers import parse_json_bytes, validate_request_payload
from omnidim_ui.proxy import build_url, execute_proxy_request, validate_upstream_url
from omnidim_ui.security import compute_danger_signature, redact_payload
from portal_core.auth import get_membership
from portal_core.models import (
    Confirmation,
    LoginThrottle,
    Membership,
    Operation,
    RateWindow,
    RequestHistory,
    SavedPayload,
    SecurityEvent,
    Workspace,
)

logger = logging.getLogger(__name__)


class ApiError(Exception):
    def __init__(self, message, status=400, code="invalid_request", **extra):
        self.message, self.status, self.code, self.extra = message, status, code, extra


def fail(message, status=400, code="invalid_request", **extra):
    raise ApiError(message, status, code, **extra)


def event(request, name, workspace=None, **details):
    SecurityEvent.objects.create(actor=request.user if request.user.is_authenticated else None, workspace=workspace, event=name, details=details)


class PortalLogin(LoginView):
    template_name = "login.html"
    redirect_authenticated_user = True

    def post(self, request, *args, **kwargs):
        now = timezone.now()
        window = int(now.timestamp()) // 900
        address = request.META.get("HTTP_X_REAL_IP", "") if settings.PORTAL_TRUST_PROXY else request.META.get("REMOTE_ADDR", "")
        identifiers = [("account:" + request.POST.get("username", "").casefold()[:150], 10), ("ip:" + address[:100], 100)]
        for identifier, limit in identifiers:
            key = hashlib.sha256(identifier.encode()).hexdigest()
            with transaction.atomic():
                counter, _ = LoginThrottle.objects.get_or_create(key_hash=key, window=window, defaults={"expires_at": now + timedelta(minutes=30)})
                LoginThrottle.objects.filter(pk=counter.pk).update(count=F("count") + 1)
                counter.refresh_from_db()
                if counter.count > limit:
                    return HttpResponse("Too many sign-in attempts. Try again in 15 minutes.", status=429, headers={"Retry-After": "900"})
        return super().post(request, *args, **kwargs)

    def form_valid(self, form):
        response = super().form_valid(form)
        event(self.request, "login")
        return response


@login_required
def index(request):
    return HttpResponse((settings.BASE_DIR / "static" / "index.html").read_text(encoding="utf-8").replace('href="styles.css"', 'href="/static/styles.css"').replace('src="app.js"', 'src="/static/app.js"'), content_type="text/html")


def csrf_failure(request, reason=""):
    return JsonResponse({"error": "Session verification failed. Reload and try again.", "code": "csrf_failed"}, status=403)


def live(request):
    return JsonResponse({"ok": True})


def ready(request):
    try:
        Membership.objects.exists()
        return JsonResponse({"ok": True})
    except DatabaseError:
        return JsonResponse({"ok": False}, status=503)


def allow(request, *methods):
    if request.method not in methods:
        fail("Method not allowed.", 405, "method_not_allowed")


def writable(membership, admin=False):
    if settings.PORTAL_READ_ONLY or not (membership.can_admin if admin else membership.can_write):
        raise PermissionDenied("Your role does not allow this action.")


def configuration(membership):
    workspace = membership.workspace
    return {"baseUrl": workspace.base_url, "hasApiKey": bool(workspace.api_key_ciphertext), "apiKeySource": "workspace" if workspace.api_key_ciphertext else "none", "apiKeyPreview": "Encrypted workspace credential" if workspace.api_key_ciphertext else "", "retentionLimit": workspace.retention_limit, "readOnly": settings.PORTAL_READ_ONLY or not membership.can_write, "canManageSettings": membership.can_admin and not settings.PORTAL_READ_ONLY, "role": membership.role}


def signature(workspace, method, path, query, body):
    payload = f"{workspace.pk}|{workspace.api_key_ciphertext}|{compute_danger_signature(method, path, query, body)}"
    return hashlib.sha256(payload.encode()).hexdigest()


def budget(request, workspace, scope, seconds, limit):
    now = timezone.now()
    window = int(now.timestamp()) // seconds
    total = RateWindow.objects.filter(workspace=workspace, scope=scope, window=window).aggregate(total=Sum("count"))["total"] or 0
    if total >= limit:
        fail("Workspace request limit reached. Try again later.", 429, "rate_limited")
    counter, _ = RateWindow.objects.get_or_create(workspace=workspace, user=request.user, scope=scope, window=window, defaults={"expires_at": now + timedelta(seconds=seconds * 2)})
    RateWindow.objects.filter(pk=counter.pk).update(count=F("count") + 1)


def prepare(request, membership, data):
    method, path, query, body, endpoint = validate_request_payload(data)
    if method != "GET":
        writable(membership)
    if endpoint.get("group") in {"Admin", "Reseller", "Reseller/Admin"} and not membership.can_admin:
        raise PermissionDenied("This action requires an administrator.")
    workspace = membership.workspace
    url = build_url(workspace.base_url, path, query)
    validate_upstream_url(url)
    return method, path, query, body, endpoint, url, signature(workspace, method, path, query, body)


def run(request, membership, data):
    method, path, query, body, endpoint, url, sig = prepare(request, membership, data)
    workspace = membership.workspace
    operation = None
    with transaction.atomic():
        workspace = Workspace.objects.select_for_update().get(pk=workspace.pk)
        if sig != signature(workspace, method, path, query, body):
            fail("Connection settings changed. Review the request again.", 409, "workspace_changed")
        if method != "GET":
            key = request.headers.get("Idempotency-Key", "")
            if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", key):
                fail("A unique Idempotency-Key is required for changes.")
            previous = Operation.objects.filter(workspace=workspace, idempotency_key=key).first()
            if previous:
                if previous.user_id != request.user.pk or previous.signature != sig:
                    fail("This request key is already used.", 409, "idempotency_conflict")
                if previous.state in {"pending", "unknown"}:
                    code = "operation_pending" if previous.state == "pending" else "operation_uncertain"
                    fail("The original request outcome is not confirmed. Check upstream activity before taking further action.", 409, code, operationId=previous.pk)
                if previous.response is None:
                    fail("The recorded response has expired. This action will not be repeated.", 409, "response_expired", operationId=previous.pk)
                return JsonResponse({**previous.response, "replayed": True})
            if Operation.objects.filter(workspace=workspace, state="pending").count() >= 4:
                fail("Workspace has too many actions in progress.", 429, "rate_limited")
            if is_dangerous_operation(endpoint, body):
                token = data.get("confirmToken", "")
                changed = Confirmation.objects.filter(token_hash=hashlib.sha256(token.encode()).hexdigest(), user=request.user, workspace=workspace, signature=sig, consumed_at__isnull=True, expires_at__gt=timezone.now()).update(consumed_at=timezone.now())
                if changed != 1:
                    fail("Review and confirm this action before sending it.", 403, "confirmation_required")
        budget(request, workspace, "requests-minute", 60, workspace.actions_per_minute)
        budget(request, workspace, "requests-day", 86400, workspace.actions_per_day)
        api_key = workspace.get_api_key()
        if not api_key:
            fail("Ask an administrator to configure the workspace API key.", 400, "connection_missing")
        if method != "GET":
            operation = Operation.objects.create(workspace=workspace, user=request.user, idempotency_key=key, signature=sig, method=method, path=path, endpoint_id=endpoint["id"])
            event(request, "operation_queued", workspace, operationId=operation.pk, endpointId=endpoint["id"])
    started = time.monotonic()
    try:
        status, ok, payload = execute_proxy_request(method, url, api_key, body)
    except Exception:
        logger.exception("Upstream request failed; request_id=%s", request.request_id)
        status, ok, payload = None, False, {"error": "Upstream did not provide a complete response."}
    duration = int((time.monotonic() - started) * 1000)
    response = {"ok": ok, "status": status, "durationMs": duration, "data": payload}
    uncertain = operation is not None and (status is None or status >= 500)
    if operation:
        response["operationId"] = operation.pk
        if uncertain:
            response.update(code="operation_uncertain", error="The outcome is unknown. Check upstream activity before taking further action.")
        durable = redact_payload(response)
        if len(json.dumps(durable)) > 200000:
            durable = {**response, "data": {"notice": "Response too large to retain. Check upstream activity."}}
        try:
            with transaction.atomic():
                Operation.objects.filter(pk=operation.pk).update(state="unknown" if uncertain else "succeeded" if ok else "failed", status=status, response=durable, updated_at=timezone.now())
                event(request, "operation_finished", workspace, operationId=operation.pk, status=status, uncertain=uncertain)
        except DatabaseError:
            logger.error("Operation result persistence failed; operation_id=%s", operation.pk)
            response["warning"] = "Result received, but activity storage failed. Do not repeat this action."
    try:
        RequestHistory.objects.create(workspace=workspace, actor=request.user, endpoint_id=endpoint["id"], method=method, path=path, status=status, ok=ok, duration_ms=duration)
        obsolete = list(RequestHistory.objects.filter(workspace=workspace).values_list("pk", flat=True)[workspace.retention_limit:workspace.retention_limit + 100])
        RequestHistory.objects.filter(pk__in=obsolete).delete()
    except DatabaseError:
        logger.error("History persistence failed; request_id=%s", request.request_id)
        response["warning"] = "Result received, but activity storage failed."
    return JsonResponse(response, status=502 if uncertain or status is None else 200)


def api(request, route):
    try:
        if not request.user.is_authenticated or not request.user.is_active:
            fail("Sign in to continue.", 401, "authentication_required")
        if route == "session":
            allow(request, "GET")
            memberships = list(Membership.objects.filter(user=request.user, is_active=True).select_related("workspace"))
            if "active_workspace_id" not in request.session and memberships:
                request.session["active_workspace_id"] = memberships[0].workspace_id
            membership = get_membership(request)
            return JsonResponse({"authenticated": True, "hosted": True, "csrfToken": get_token(request), "user": {"id": request.user.pk, "username": request.user.get_username()}, "workspace": {"id": membership.workspace_id, "name": membership.workspace.name}, "role": membership.role, "workspaces": [{"id": item.workspace_id, "name": item.workspace.name, "role": item.role} for item in memberships]})
        if route == "logout":
            allow(request, "POST")
            event(request, "logout")
            logout(request)
            return JsonResponse({"ok": True})
        data = parse_json_bytes(request.body) if request.method in {"POST", "PUT", "PATCH"} else {}
        if route == "workspace":
            allow(request, "POST")
            identifier = data.get("workspaceId")
            if isinstance(identifier, bool) or not str(identifier).isdigit():
                fail("Invalid workspace.")
            membership = Membership.objects.filter(user=request.user, workspace_id=int(identifier), is_active=True).first()
            if not membership:
                raise PermissionDenied("Workspace access is unavailable.")
            request.session["active_workspace_id"] = membership.workspace_id
            event(request, "workspace_selected", membership.workspace)
            return JsonResponse({"ok": True})
        membership = get_membership(request)
        workspace = membership.workspace
        if request.headers.get("X-Workspace-ID") != str(workspace.pk):
            fail("Workspace changed. Reload before continuing.", 409, "workspace_changed")
        if route == "endpoints":
            allow(request, "GET")
            return JsonResponse({"endpoints": ENDPOINTS, "groups": GROUPS})
        if route in {"settings", "settings/api-key"}:
            allow(request, *( ["DELETE"] if route.endswith("api-key") else ["GET", "PUT"]))
            if request.method != "GET":
                writable(membership, admin=True)
                with transaction.atomic():
                    workspace = Workspace.objects.select_for_update().get(pk=workspace.pk)
                    membership.workspace = workspace
                    if request.method == "DELETE":
                        workspace.set_api_key("")
                    else:
                        if "baseUrl" in data:
                            validate_upstream_url(data["baseUrl"])
                            if data["baseUrl"].rstrip("/") != "https://omnidim.io/api/v1":
                                fail("Use the OmniDimension API base URL.")
                            workspace.base_url = data["baseUrl"].rstrip("/")
                        if "retentionLimit" in data:
                            if isinstance(data["retentionLimit"], bool) or not isinstance(data["retentionLimit"], int):
                                fail("Retention limit must be an integer.")
                            workspace.retention_limit = data["retentionLimit"]
                        if "apiKey" in data:
                            if not isinstance(data["apiKey"], str) or not 1 <= len(data["apiKey"]) <= 4096:
                                fail("Invalid API key.")
                            workspace.set_api_key(data["apiKey"])
                    workspace.full_clean()
                    workspace.save()
                    event(request, "settings_updated", workspace)
            return JsonResponse(configuration(membership))
        if route == "preflight":
            allow(request, "POST")
            method, path, query, body, endpoint, url, sig = prepare(request, membership, data)
            danger = is_dangerous_operation(endpoint, body)
            result = {"ok": True, "danger": danger}
            if danger:
                token = secrets.token_urlsafe(32)
                with transaction.atomic():
                    Workspace.objects.select_for_update().get(pk=workspace.pk)
                    budget(request, workspace, "confirm-minute", 60, 30)
                    Confirmation.objects.create(token_hash=hashlib.sha256(token.encode()).hexdigest(), user=request.user, workspace=workspace, method=method, path=path, signature=sig, expires_at=timezone.now() + timedelta(seconds=60))
                result.update(confirmToken=token, requiredConfirm=endpoint.get("confirm", "CONFIRM"), expiresInSeconds=60)
            return JsonResponse(result)
        if route == "run":
            allow(request, "POST")
            return run(request, membership, data)
        if route.startswith("operations/"):
            allow(request, "GET")
            item = Operation.objects.filter(pk=int(route.split("/")[1]), workspace=workspace, user=request.user).first()
            if not item:
                fail("Operation not found.", 404, "not_found")
            return JsonResponse({"id": item.pk, "state": item.state, "response": item.response})
        if route == "history":
            allow(request, "GET", "DELETE")
            records = RequestHistory.objects.filter(workspace=workspace)
            if request.method == "DELETE":
                writable(membership, admin=True)
                with transaction.atomic():
                    records.delete()
                    event(request, "history_cleared", workspace)
                return JsonResponse({"ok": True})
            search = request.GET.get("search", "")[:200]
            if search:
                records = records.filter(Q(path__icontains=search) | Q(endpoint_id__icontains=search))
            page = max(1, min(int(request.GET.get("page", 1)), 100000))
            page_size = max(1, min(int(request.GET.get("pageSize", 20)), 100))
            total = records.count()
            return JsonResponse({"items": list(records.values("id", "created_at", "method", "path", "status", "ok", "duration_ms")[(page - 1) * page_size:page * page_size]), "page": page, "total": total, "totalPages": max(1, math.ceil(total / page_size))})
        if route == "saved-payloads" or route.startswith("saved-payloads/"):
            return saved(request, membership, route, data)
        fail("Page not found.", 404, "not_found")
    except ApiError as exc:
        return JsonResponse({"error": exc.message, "code": exc.code, **exc.extra}, status=exc.status)
    except PermissionDenied as exc:
        return JsonResponse({"error": str(exc), "code": "forbidden"}, status=403)
    except (ValueError, TypeError, ValidationError, PermissionError):
        return JsonResponse({"error": "Invalid request. Check the values and try again.", "code": "invalid_request"}, status=400)
    except DatabaseError:
        logger.exception("Database unavailable; request_id=%s", request.request_id)
        return JsonResponse({"error": "Activity storage is unavailable. Try again later.", "code": "storage_unavailable"}, status=503)


def saved(request, membership, route, data):
    records = SavedPayload.objects.filter(workspace=membership.workspace, owner=request.user)
    if route != "saved-payloads":
        allow(request, "DELETE")
        writable(membership)
        deleted, _ = records.filter(pk=int(route.split("/")[1])).delete()
        if not deleted:
            fail("Saved request not found.", 404, "not_found")
        return JsonResponse({"ok": True})
    allow(request, "GET", "POST")
    if request.method == "POST":
        writable(membership)
        method, path, query, body, endpoint = validate_request_payload(data)
        name = data.get("name", "")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 150 or len(json.dumps(data)) > 200000:
            fail("Use a name up to 150 characters and a request under 200 KB.")
        with transaction.atomic():
            Workspace.objects.select_for_update().get(pk=membership.workspace_id)
            if records.count() >= 1000:
                fail("Saved request limit reached.", 429, "quota_exceeded")
            records.update_or_create(endpoint_id=endpoint["id"], name=name.strip(), defaults={"workspace": membership.workspace, "owner": request.user, "method": method, "path": path, "query_json": redact_payload(query), "body_json": redact_payload(body)})
    return JsonResponse({"records": [{"id": item.pk, "endpoint_id": item.endpoint_id, "name": item.name, "method": item.method, "path": item.path, "query_json": json.dumps(item.query_json), "body_json": json.dumps(item.body_json)} for item in records[:1000]]})
