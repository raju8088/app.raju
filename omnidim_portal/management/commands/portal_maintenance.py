from datetime import timedelta

from django.conf import settings
from django.contrib.sessions.models import Session
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from portal_core.models import Confirmation, LoginThrottle, Operation, RateWindow, RequestHistory, SecurityEvent


class Command(BaseCommand):
    help = "Expire temporary records and response bodies, preserving durable action identity and audit records."

    def handle(self, *args, **options):
        now = timezone.now()
        with transaction.atomic():
            stale = Operation.objects.select_for_update().filter(state="pending", created_at__lt=now - timedelta(minutes=5))
            for operation in stale:
                operation.state = "unknown"
                operation.updated_at = now
                operation.save(update_fields=["state", "updated_at"])
                SecurityEvent.objects.create(workspace=operation.workspace, actor=operation.user, event="operation_stale", details={"operationId": operation.pk})
            for model in (Confirmation, RateWindow, LoginThrottle):
                model.objects.filter(expires_at__lt=now).delete()
            Session.objects.filter(expire_date__lt=now).delete()
            cutoff = now - timedelta(days=settings.PORTAL_HISTORY_DAYS)
            RequestHistory.objects.filter(created_at__lt=cutoff).delete()
            Operation.objects.filter(created_at__lt=cutoff).exclude(state="pending").update(response=None)
        self.stdout.write(self.style.SUCCESS("Temporary records expired; operation identities and audit preserved."))
