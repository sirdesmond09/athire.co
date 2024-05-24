from accounts.permissions import *
from accounts.signals import comfirmaion_email
from config import settings
from .serializers import *
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework_simplejwt.authentication import JWTAuthentication
from drf_yasg.utils import swagger_auto_schema
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import logout
from django.contrib.auth.signals import user_logged_out
from djoser.views import UserViewSet
from rest_framework import generics
from django.contrib.auth.hashers import check_password
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .serializers import OTPVerifySerializer
from .models import OTP
from django.core.mail import send_mail
import json, time
from .helpers.encryptors import data_encryptor
import hashlib


class OTPVerifyView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = OTPVerifySerializer

    def post(self, request):
        serializer = OTPVerifySerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        return Response(
            {
                "message": "OTP verified successfully",
                "payload": CustomUserSerializer(request.user).data,
            }
        )


class SignupOTPVerifyView(generics.CreateAPIView):
    permission_classes = [
        AllowAny,
    ]
    serializer_class = OTPVerifySerializer

    def post(self, request):

        otp = request.data.get("otp")
        otp_hash = hashlib.sha256(otp.encode()).hexdigest()
        inst = OTP.objects.filter(otp_hash=otp_hash, created_at__gte=(now() - timedelta(minutes=5)).isoformat()
        )

        if not inst.exists():
            raise serializers.ValidationError("Invalid or expired OTP")
        user = inst.first().user
        user.is_active = True
        user.save()

        comfirmaion_email(user)

        return Response(
            {
                "message": "OTP verified successfully",
            }
        )


@swagger_auto_schema(method="post", request_body=EncryptionSerializer())
@api_view(["POST"])
def user_login(request):
    encryption = EncryptionSerializer(data=request.data)
    encryption.is_valid(raise_exception=True)
    data = json.loads(data_encryptor.decrypt(encryption.validated_data.get("payload")))

    email = data["email"]
    password = data["password"]

    try:
        user = User.objects.get(email=email)
        if user.check_password(password):
            otp = OTP.generate_otp(user)
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            send_mail(
                "Your OTP Code",
                f"Dear User, \n\nYour OTP code for login is: {otp}. \n\nBest regards, \nAthire.co Team",
                settings.Common.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            return Response({"detail": "OTP sent to email", "access_token": access_token, "refresh_token": refresh_token})
        else:
            return Response({"detail": "Invalid credentials"}, status=400)
    except User.DoesNotExist:
        return Response({"detail": "Invalid credentials"}, status=400)


class CustomUserViewSet(UserViewSet):
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
       request_body=CustomUserSerializer,
        operation_description="List all users",
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)
    
    def list(self, request, *args, **kwargs):

        page = self.paginate_queryset(self.queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(self.queryset, many=True)
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        password = serializer.validated_data.get("current_password")

        if check_password(password, instance.password):

            self.perform_destroy(instance)
            return Response(status=status.HTTP_204_NO_CONTENT)

        elif request.user.role == "admin" and check_password(
            password, request.user.password
        ):
            self.perform_destroy(instance)
            return Response(status=status.HTTP_204_NO_CONTENT)

        # elif password=="google" and request.user.provider=="google":
        #     self.perform_destroy(instance)
        #     return Response(status=status.HTTP_204_NO_CONTENT)
        else:
            raise AuthenticationFailed(detail={"message": "incorrect password"})


@swagger_auto_schema(method="post", request_body=LogoutSerializer())
@api_view(["POST"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """Log out a user by blacklisting their refresh token then making use of django's internal logout function to flush out their session and completely log them out.

    Returns:
        Json response with message of success and status code of 204.
    """

    serializer = LogoutSerializer(data=request.data)

    serializer.is_valid(raise_exception=True)

    try:
        token = RefreshToken(token=serializer.validated_data["refresh_token"])
        token.blacklist()
        user = request.user
        user_logged_out.send(sender=user.__class__, request=request, user=user)
        logout(request)

        return Response({"message": "success"}, status=status.HTTP_204_NO_CONTENT)
    except TokenError:
        return Response(
            {"message": "failed", "error": "Invalid refresh token"},
            status=status.HTTP_400_BAD_REQUEST,
        )


# @swagger_auto_schema(methods=["POST"], request_body=NewOtpSerializer())
# @api_view(["POST"])
# def reset_otp(request):
#     if request.method == "POST":
#         serializer = NewOtpSerializer(data=request.data)
#         if serializer.is_valid():
#             data = serializer.get_new_otp()

#             return Response(data, status=status.HTTP_200_OK)

#         else:
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# @swagger_auto_schema(methods=["POST"], request_body=OTPVerifySerializer())
# @api_view(["POST"])
# def otp_verification(request):
#     """Api view for verifying OTPs"""

#     if request.method == "POST":

#         serializer = OTPVerifySerializer(data=request.data)

#         if serializer.is_valid():
#             data = serializer.verify_otp(request)

#             return Response(data, status=status.HTTP_200_OK)
#         else:

#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
