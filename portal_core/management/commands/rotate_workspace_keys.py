from django.core.management.base import BaseCommand
from django.db import transaction

from portal_core.models import SecurityEvent, Workspace
from portal_core.secrets import rotate_api_key


class Command(BaseCommand):
    help = "Atomically re-encrypt workspace credentials with OMNIDIM_ENCRYPTION_KEY using configured previous keys."

    def handle(self, *args, **options):
        count = 0
        with transaction.atomic():
            for workspace in Workspace.objects.select_for_update().exclude(api_key_ciphertext="").iterator():
                workspace.api_key_ciphertext = rotate_api_key(workspace.api_key_ciphertext)
                workspace.save(update_fields=["api_key_ciphertext"])
                SecurityEvent.objects.create(workspace=workspace, event="workspace.credential_rotated", details={"source": "management_command"})
                count += 1
        self.stdout.write(self.style.SUCCESS(f"Rotated {count} workspace credential(s)."))
