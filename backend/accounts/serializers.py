from djoser.serializers import UserCreateSerializer as BaseUserRegistrationSerializer
from django.contrib.auth import get_user_model
from rest_framework import serializers
from djoser.signals import user_activated
from django.utils import timezone
from django.core.mail import send_mail
from django.template.loader import render_to_string
from rest_framework.exceptions import ValidationError
from django.contrib.auth.models import Permission, Group
from drf_extra_fields.fields import Base64ImageField

from django.utils.timezone import now, timedelta

from .models import OTP
import hashlib


User = get_user_model()


class UserRegistrationSerializer(BaseUserRegistrationSerializer):

    class Meta(BaseUserRegistrationSerializer.Meta):
        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "role",
            "phone",
            "password",
            "is_active",
        ]


class UserDeleteSerializer(serializers.Serializer):
    current_password = serializers.CharField(style={"input_type": "password"})


class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        style={"input_type": "password"}, write_only=True, required=False
    )
    humanized_phone = serializers.ReadOnlyField()

    class Meta:
        model = User
        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "phone",
            "humanized_phone",
            "password",
            "date_joined",
        ]

        extra_kwargs = {"password": {"write_only": True}, "phone": {"write_only": True}}


class EncryptionSerializer(serializers.Serializer):
    payload = serializers.CharField(max_length=5000)
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(max_length=5000)


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(max_length=700)


class OTPVerifySerializer(serializers.Serializer):
    otp = serializers.CharField()

    def validate_otp(self, value):
        user = self.context["request"].user
        otp_hash = hashlib.sha256(value.encode()).hexdigest()
        
        if not OTP.objects.filter(
            user=user, otp_hash=otp_hash, created_at__gte=(now() - timedelta(minutes=5)).isoformat()
        ).exists():
            raise serializers.ValidationError("Invalid or expired OTP")
        return value
