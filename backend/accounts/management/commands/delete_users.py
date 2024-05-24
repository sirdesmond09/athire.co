from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model

User = get_user_model()

class Command(BaseCommand):
    help = 'Create Dummy Box locations'


    def handle(self, *args, **options):
    
        User.objects.all().delete()
        
        self.stdout.write(self.style.SUCCESS("Successfully deleted users"))