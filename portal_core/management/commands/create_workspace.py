from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError, transaction

from portal_core.models import Membership, SecurityEvent, Workspace


class Command(BaseCommand):
    help = "Create a workspace and grant administrator membership to an existing active user."

    def add_arguments(self, parser):
        parser.add_argument("--name", required=True)
        parser.add_argument("--slug", required=True)
        parser.add_argument("--owner", required=True, help="Existing owner's username")

    def handle(self, *args, **options):
        user_model = get_user_model()
        try:
            owner = user_model.objects.get(**{user_model.USERNAME_FIELD: options["owner"], "is_active": True})
        except user_model.DoesNotExist as exc:
            raise CommandError("The workspace owner must be an existing active user.") from exc
        try:
            with transaction.atomic():
                workspace = Workspace(name=options["name"].strip(), slug=options["slug"].strip())
                workspace.full_clean()
                workspace.save()
                Membership.objects.create(workspace=workspace, user=owner, role=Membership.Role.ADMIN)
                SecurityEvent.objects.create(workspace=workspace, actor=owner, event="workspace.created", details={"source": "management_command"})
        except (IntegrityError, ValidationError) as exc:
            raise CommandError("Workspace creation failed. Check its name and unique slug.") from exc
        self.stdout.write(self.style.SUCCESS(f"Created workspace '{workspace.slug}' and its administrator membership."))
