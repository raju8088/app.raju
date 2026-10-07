"""Resolve tenancy from authenticated database membership, never from input alone."""

from collections.abc import Iterable
from functools import wraps

from django.core.exceptions import PermissionDenied
from django.http import HttpRequest

from portal_core.models import Membership


def get_membership(request: HttpRequest, roles: Iterable[str] | None = None) -> Membership:
    """Return a currently active membership or fail closed.

    Read membership on every request so revocation/role changes take effect
    immediately. A stale or manipulated active workspace never falls through
    into a different workspace. No superuser shortcut bypasses membership.
    """
    if not request.user.is_authenticated or not request.user.is_active:
        raise PermissionDenied("Sign in to access a workspace.")
    memberships = Membership.objects.select_related("workspace").filter(user=request.user, is_active=True)
    active = request.session.get("active_workspace_id")
    if active is not None:
        if isinstance(active, bool) or not isinstance(active, (str, int)):
            raise PermissionDenied("Select an available workspace.")
        try:
            active_id = int(active)
            membership = memberships.filter(workspace_id=active_id).first() if active_id > 0 else None
        except (ValueError, TypeError, OverflowError):
            membership = None
        if membership is None:
            raise PermissionDenied("Your workspace access has changed. Select an available workspace.")
    else:
        candidates = list(memberships.order_by("pk")[:2])
        if len(candidates) != 1:
            raise PermissionDenied("Select an available workspace.")
        membership = candidates[0]
        request.session["active_workspace_id"] = membership.workspace_id
    if roles is not None and membership.role not in set(roles):
        raise PermissionDenied("Your role does not allow this action.")
    return membership


def require_membership(*roles: str):
    """Attach request.membership after validating the requested workspace role."""
    def decorate(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            request.membership = get_membership(request, roles or None)
            return view(request, *args, **kwargs)
        return wrapped
    return decorate
