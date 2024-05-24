from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.base_user import AbstractBaseUser
from django.utils.translation import gettext_lazy as _
from .managers import UserManager
import uuid, hashlib, hmac, time, os, random
from phonenumber_field.modelfields import PhoneNumberField


class User(AbstractBaseUser, PermissionsMixin):
    """
    Database schema for User model.

    Fields:
        - id (UUID): Unique identifier for the user.
        - first_name (str): First name of the user
        - last_name (str): Last name of the user
        - email (str): Email address of the user.
        - role (str): User type i.e admin, user, vendor.
        - image (img): profile picture of users
        - password (str): Password of the users
        - is_staff (bool): Field to mark an admin user as a super admin
        - is_active (bool): Active status of the user
        - is_deleted (bool): Deleted status of the user
        - fcm_token (str): User's device firebase token for push notification
        - provider (str): Channel through which user signed up.
        - date_joined (datetime): Time at which the user signed up.
    """

    ROLE_CHOICES = (
        ("admin", "Admin"),
        ("user", "User"),
    )

    id = models.UUIDField(
        primary_key=True, unique=True, editable=False, default=uuid.uuid4
    )
    first_name = models.CharField(_("first name"), max_length=250)
    last_name = models.CharField(_("last name"), max_length=250)
    role = models.CharField(_("role"), max_length=255, choices=ROLE_CHOICES)
    email = models.EmailField(_("email"), unique=True)
    phone = PhoneNumberField(_("phone"), unique=True)
    password = models.CharField(_("password"), max_length=300)
    is_staff = models.BooleanField(_("staff"), default=False)
    is_active = models.BooleanField(_("active"), default=True)
    date_joined = models.DateTimeField(_("date joined"), auto_now_add=True)
    provider = models.CharField(
        _("provider"),
        max_length=255,
        default="email",
        choices=(("email", "email"), ("google", "google")),
    )

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = [
        "id",
        "first_name",
        "last_name",
        "phone",
        "role",
    ]

    class Meta:
        verbose_name = _("user")
        verbose_name_plural = _("users")

    def __str__(self):
        return f"{self.email} -- {self.role}"
    
    @property
    def humanized_phone(self):
        return str(self.phone)


class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)

    @staticmethod
    def generate_otp(user):
        otp = str(random.randint(100000, 999999))
        otp_hash = hashlib.sha256(otp.encode()).hexdigest()
        OTP.objects.create(user=user, otp_hash=otp_hash)
        return otp


