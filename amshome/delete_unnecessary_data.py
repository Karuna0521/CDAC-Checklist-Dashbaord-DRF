
from datetime import timedelta, timezone
from django.core.management.base import BaseCommand
from .models import Captcha

class Command(BaseCommand):
    help = 'Delete unnecessary data'

    def handle(self, *args, **options):
        # Define your deletion criteria here
        threshold_date = timezone.now() - timedelta(minutes=5)

        # Delete records that meet the criteria
        deleted_count, _ = Captcha.objects.filter(created_at__lt=threshold_date).delete()
        self.stdout.write(self.style.SUCCESS(f'Deleted {deleted_count} records'))
