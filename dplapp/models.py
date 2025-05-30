# Create your models here.

from django.db import models
import uuid
from django.db.models import Q

from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from django.core.exceptions import ValidationError

import re

import hashlib

from django.contrib import admin

import logging
logger = logging.getLogger()

# import logging
# logger = logging.getLogger()

from django.utils import timezone

import datetime

from argon2 import PasswordHasher
import argon2.exceptions

from datetime import timedelta

import ipaddress

from django.core.exceptions import ImproperlyConfigured

def ReturnTrue():
    return True

def ReturnFalse():
    return False

def ReturnEmptyString():
    return ""

class UsersModel(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    additional_data = models.TextField(blank=True, default="")
    last_login = models.DateTimeField(blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True, blank=True, null=True) # 
    
    @property
    def can_login(self):

        if not hasattr(self, 'tokensmodel'):
            return False

        if not self.tokensmodel.is_active:
            return False

        activity_period = AppSettingsModel.objects.get_or_create()[0].activity_period

        now_timestamp = timezone.now().astimezone(datetime.timezone.utc)

        token_timestamp = self.tokensmodel.last_activated.astimezone(datetime.timezone.utc)

        last_login = self.last_login
        if last_login:
            last_login = last_login.astimezone(datetime.timezone.utc)

        if (now_timestamp - token_timestamp) > activity_period:
            return False
        

        if last_login and ((now_timestamp - last_login) < (activity_period+timedelta(seconds=1))):
            return False


        self.last_login = now_timestamp
        self.save()

        return True
    

    pass

class TokensModel(models.Model):

    def validate_public_key(value: str):
        from dplapp.utils import pubkey_validation # utils import pubkey_validation
        retval = pubkey_validation(value)
        if retval:
            raise ValidationError(retval)
        return value
    

    def validate_ips(value: str):

        value = list(set(value.replace(' ', '').split(',')))

        for ipaddr in value:
            is_ip = True
            is_network = True

            try:
                ipaddress.ip_address(ipaddr)
            except ValueError:
                is_ip = False

            try:
                ipaddress.ip_network(ipaddr)
            except ValueError:
                is_network = False

            if not is_ip and not is_network:
                raise ValidationError(f"{ipaddr=} doesnt appear to be a valid IP or netmask")                


    def validate_pin(value: str):
        try:
            ph = PasswordHasher()
            ph.verify(value, "not_a_password")
        except argon2.exceptions.VerifyMismatchError: pass
        except argon2.exceptions.InvalidHashError as exc:
            raise ValidationError(f"not a valid argon2 hash") from exc
            

    pubkey = models.TextField(unique=True, validators=[validate_public_key])
    is_active = models.BooleanField(default=ReturnTrue)
    can_reset_password = models.BooleanField(default=ReturnFalse)
    last_activated = models.DateTimeField(blank=True, null=True)
    user = models.OneToOneField(UsersModel, on_delete=models.SET_NULL, null=True, blank=True)
    pin = models.TextField()
    allowed_ips = models.TextField(blank=True, validators=[validate_ips], default=ReturnEmptyString)
    fingerprint = models.CharField(max_length=17, editable=False, blank=True)
    # pin_salt = models.TextField()


    # @property
    # def pubkey(self):
    #     return re.sub(r'(\r\n)|\n', '', self._pubkey)
    
    # @pubkey.setter
    # def pubkey(self, value):
    #     if value:
    #         value = re.sub(r'(\r\n)|\n', '', value)
    #     self._pubkey = value


    # @property
    # @admin.display(description = 'Fingerprint')
    # def fingerprint(self):
    #     cleaned_pubkey = re.sub(r'(\r\n)|\n', '', self.pubkey)
    #     digest = hashlib.sha256(cleaned_pubkey.encode('utf-8')).digest()
    #     first_6_bytes = digest[:6]
    #     return ' '.join(f'{byte:02X}' for byte in first_6_bytes)

    def save(self, *args, **kwargs):

        self.full_clean()

        # print(f"started save, {self.pubkey=}, {self.fingerprint=}")
        if self.pubkey:
            # print("found pubkey")
            cleaned_pubkey = re.sub(r'(\r\n)|\n', '', self.pubkey)
            digest = hashlib.sha256(cleaned_pubkey.encode('utf-8')).digest()
            first_6_bytes = digest[:6]
            fingerprint = ' '.join(f'{byte:02X}' for byte in first_6_bytes)
            # print(f"{fingerprint=}")
            self.fingerprint = fingerprint
            # print(f"{self.fingerprint=}")

        super(TokensModel, self).save(*args, **kwargs)


    pass



class AppSettingsModel(models.Model):
    # ticket_validity_period = models.DurationField(blank=True, null=True) # when less than that time left before ticket expires, auto update the ticket
    ticket_expiry_period = models.DurationField(blank=True, null=True)
    singleton_enforcer = models.CharField(max_length=1, unique=True, default='X', editable=False, choices={'X': 'X'})
    OFF = "of"; ON = "on"; GRACEFUL = "gr"; DEV = "dv"
    ENFORCING_MODES = {
        OFF: 'off',
        ON: 'on',
        GRACEFUL: 'graceful',
        DEV: 'dev',
    }
    enforcing_mode = models.CharField(max_length=2, choices=ENFORCING_MODES, blank=True, null=True)

    @property
    def validate_existing(self):
        if self.enforcing_mode in [self.ON, self.GRACEFUL]:
            return True
        elif self.enforcing_mode in [self.OFF, self.DEV]:
            return False
        else:
            raise ImproperlyConfigured(f"unexpected enforcing_mode value: {self.enforcing_mode}, did you forget to run setup_app?")

    @property
    def allow_new(self):
        if self.enforcing_mode in [self.OFF, self.GRACEFUL]:
            return True
        elif self.enforcing_mode in [self.ON, self.DEV]:
            return False
        else:
            raise ImproperlyConfigured(f"unexpected enforcing_mode value: {self.enforcing_mode}, did you forget to run setup_app?")

    activity_period = models.DurationField(blank=True, null=True)
    admin_panel_token = models.UUIDField(blank=True, null=True)
    public_key = models.TextField(blank=True)
    private_key = models.TextField(blank=True)
    ticket_encryption_key = models.BinaryField(blank=True, editable=True)

    def save(self, *args, **kwargs):
        self.full_clean()
        super(AppSettingsModel, self).save(*args, **kwargs)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(activity_period__lt = models.F("ticket_expiry_period")) ,
                name="activity_period__lt__ticket_expiry_period",
            )
        ]

    pass


class HistoryModel(models.Model):
    datetime = models.DateTimeField(auto_now_add=True)
    token = models.ForeignKey(TokensModel, on_delete=models.CASCADE, null=True, blank=True) # , to_field='pubkey'
    initial_data = models.TextField(blank=True, null=True)
    @property
    def additional_data(self):
        return self.token.user.additional_data
    ip = models.GenericIPAddressField()
    result = models.TextField()
    msg = models.TextField()

    pass