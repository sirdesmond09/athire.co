import random
from django.dispatch import receiver
from django.core.mail import send_mail
from django.db.models.signals import post_save, pre_save
from django.contrib.auth import get_user_model
from config import settings
from djoser.signals import user_registered, user_activated

from .models import OTP
from django.utils import timezone
from django.core.mail import send_mail
from django.template.loader import render_to_string
import json
import os
import requests


User = get_user_model()
site_name = "Athire"



@receiver(user_registered)
def activate_otp(user, request, *args, **kwargs):

    if user.role == "user":
        user.is_active = False
        user.save()

        code = OTP.generate_otp(user)

        subject = f"ACCOUNT VERIFICATION FOR {site_name}".upper()

        message = f"""Hi, {str(user.first_name).title()}.
    Thank you for signing up!
    Complete your verification on the {site_name} with the OTP below:

                    {code}        

    Expires in 5 minutes!

    Cheers,
    {site_name} Team            
    """
        

        email_from = settings.Common.DEFAULT_FROM_EMAIL
        recipient_list = [user.email]
        send_mail(subject, message, email_from, recipient_list)

        return



def comfirmaion_email(user):

    if user.role == "user":
        subject = "VERIFICATION COMPLETE"

        message = f"""Hi, {str(user.first_name).title()}.
    Your account has been activated and is ready to use!

    Cheers,
    {site_name} Team            
    """
        

        email_from = settings.Common.DEFAULT_FROM_EMAIL
        recipient_list = [user.email]
        send_mail(subject, message, email_from, recipient_list)

        return
