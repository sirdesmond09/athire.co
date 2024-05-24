from rest_framework_simplejwt.token_blacklist import models, admin


class CustomOutstandingTokenAdmin(admin.OutstandingTokenAdmin):
    
    def has_delete_permission(self, *args, **kwargs):
        return True # or whatever logic you want

from django.contrib import admin
from accounts.models import  User, OTP

# Register your models here.
    
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ["email", "role", "is_active"]

    
    
admin.site.register(OTP)
admin.site.unregister(models.OutstandingToken)
admin.site.register(models.OutstandingToken, CustomOutstandingTokenAdmin)