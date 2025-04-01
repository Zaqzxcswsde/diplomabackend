# file for serializers

import ipaddress
from rest_framework import serializers
from rest_framework.settings import api_settings
from django.conf import settings
from cryptography.fernet import InvalidToken
from dplapp.utils import decrypt_ticket_from_database, create_encrypted_ticket_from_database, pubkey_validation
from jwt.exceptions import InvalidSignatureError, DecodeError
from django.core.exceptions import ObjectDoesNotExist, ImproperlyConfigured
from django.utils import timezone
from datetime import timedelta
from dplapp.models import TokensModel, AppSettingsModel, HistoryModel, UsersModel

from dplapp.errors import ERRORS, ErrorCodes

import jwt

import json

import logging
logger = logging.getLogger()

import datetime

from argon2 import PasswordHasher
import argon2.exceptions

from django.db import transaction



class UTCDateTimeField(serializers.DateTimeField):
    def to_representation(self, value):
        if value is not None:
            # Приводим время к UTC, если оно timezone-aware
            value = value.astimezone(datetime.timezone.utc)
        return super().to_representation(value)



class UserSerializer(serializers.ModelSerializer):
    last_login = UTCDateTimeField(required = False, read_only=True)
    token = serializers.CharField(source='tokensmodel.pk', read_only=True)
    fingerprint = serializers.CharField(source='tokensmodel.fingerprint', read_only=True)

    class Meta:
        model = UsersModel
        fields = '__all__'


class TokenSerializer(serializers.ModelSerializer):

    # user_uuid = serializers.UUIDField(source='user.uuid', read_only=True)
    # fingerprint = serializers.SerializerMethodField()
    # user_additional_info = serializers.Te SerializerMethodField()
    user_additional_data = serializers.CharField(required=False, allow_blank=True) # , allow_null=True

    user = serializers.PrimaryKeyRelatedField(queryset=UsersModel.objects.all(), required=False, allow_null = True)

    user_last_login = serializers.DateTimeField(source = "user.last_login", read_only=True)

    class Meta:
        model = TokensModel
        fields = '__all__'
        read_only_fields = ['pubkey', 'pin', 'last_activated', 'fingerprint'] # 'user_additional_data'

    # def get_fingerprint(self, obj):
    #     return obj.fingerprint

    def to_internal_value(self, data : dict[str, str]):

        self.context['is_user_null'] = data.get('user', None) is None

        if data.get("allowed_ips", None):
            data["allowed_ips"] = ','.join(x for x in dict.fromkeys(data["allowed_ips"].replace(" ", "").split(',')) if x != "")

        return super().to_internal_value(data)


    def to_representation(self, instance):
        rep = super().to_representation(instance)
        
        rep['user_additional_data'] = (
            instance.user.additional_data if instance.user and instance.user.additional_data else ""
        )
        return rep


    def update(self, instance, validated_data: dict):
        new_info = validated_data.pop('user_additional_data', None)
        new_user = validated_data.get('user', None)
        if self.context['is_user_null']:
            validated_data.pop('user', None)
            # new_user = instance.user


        with transaction.atomic():

            if new_user is not None and new_user != instance.user:
                TokensModel.objects.filter(user = new_user).update(user = None)

            old_user = instance.user
            instance = super().update(instance, validated_data)

            if (new_info is not None and
                old_user is not None and
                old_user == instance.user):
                instance.user.additional_data = new_info
                instance.user.save(update_fields=['additional_data'])
                instance.user.refresh_from_db(fields=['additional_data'])

            # old_user = instance.user


        return instance

    # def validate_user(self, value):
    #     instance = getattr(self, 'instance', None)

    #     if instance and TokensModel.objects.filter(user=value).exclude(id=instance.id).exists():
    #         return value

    #     return value

    # def get_user_additional_info(self, obj):
    #     if obj.user and obj.user.additional_data:
    #         return json.dumps(obj.user.additional_data, ensure_ascii=False)
        # return None




class HistorySerializer(serializers.ModelSerializer):
    datetime = UTCDateTimeField()

    class Meta:
        model = HistoryModel
        fields = ['datetime', 'ip', 'msg']


class FullHistorySerializer(serializers.ModelSerializer):

    fingerprint = serializers.CharField(source = "token.fingerprint", read_only=True)
    datetime = UTCDateTimeField()

    class Meta:
        model = HistoryModel
        fields = '__all__'


class TicketSerializer(serializers.Serializer):

    version = serializers.CharField()
    request_time = serializers.DateTimeField()
    public_key = serializers.CharField()
    # imei = serializers.CharField()
    ip = serializers.IPAddressField()

    def to_internal_value(self, data):     

        if not isinstance(data, dict):
            raise serializers.ValidationError({
                api_settings.NON_FIELD_ERRORS_KEY: ERRORS[ErrorCodes.DATA_SHOULD_BE_DICT]
            })
        
        if list(data.keys()) != ['ticket']:
            raise serializers.ValidationError({
                api_settings.NON_FIELD_ERRORS_KEY: ERRORS[ErrorCodes.INCORRECT_DICT_KEYS_TICKET]
            })
        
        data = data['ticket']

        try:

            decrypted_obj = decrypt_ticket_from_database(data)

        except InvalidSignatureError as exc:
            raise serializers.ValidationError({
                api_settings.NON_FIELD_ERRORS_KEY: ERRORS[ErrorCodes.MALFORMED_JWT_SIGNATURE]
            }) from exc
        except DecodeError as exc:
            raise serializers.ValidationError({
                api_settings.NON_FIELD_ERRORS_KEY: ERRORS[ErrorCodes.INCORR_JWT_TICKET]
            }) from exc
        except InvalidToken as exc:
            raise serializers.ValidationError({
                api_settings.NON_FIELD_ERRORS_KEY: ERRORS[ErrorCodes.COULDNT_DECRYPT]
            }) from exc
                
        # in case exception hasn't been raised but funtion returned nothing
        if decrypted_obj is None:
            raise serializers.ValidationError({
                api_settings.NON_FIELD_ERRORS_KEY: ERRORS[ErrorCodes.ERR_IN_SIG_OR_DEC]
            })

        if not isinstance(decrypted_obj, dict):
            raise serializers.ValidationError({
                    api_settings.NON_FIELD_ERRORS_KEY: ERRORS[ErrorCodes.DEC_NOT_DICT]
            })

        return super().to_internal_value(decrypted_obj)

    def to_representation(self, instance):
        # try:

        ticket = create_encrypted_ticket_from_database(instance)
        
        # except Exception as exc:
        #     raise serializers.ValidationError({
        #             api_settings.NON_FIELD_ERRORS_KEY: f"unknown error in creating ticket"
        #     }) from exc
        return {'ticket': ticket}


    # happens after each field has been validated
    def validate(self, data):

        sett = AppSettingsModel.objects.get_or_create()[0]

        # token_exists = TokensModel.objects.filter(pubkey = data.get('public_key')).exists()

        # if token_exists and not sett.validate_existing:
        #     return data

        if not sett.validate_existing:
            return data
        

        if data['version'] != settings.APP_VERSION and data['version'] not in settings.ALLOWED_VERSIONS:
            raise serializers.ValidationError({"version": ERRORS[ErrorCodes.UNSUP_VER_TICKET]})

        # if not token_exists and not sett.allow_new:
        #     raise serializers.ValidationError({
        #         'public_key': f""
        #         })              


        # token check can be skipped because of validate_public_key
        token = TokensModel.objects.get(pubkey = data.get('public_key'))

        grace_period = timedelta(seconds=5)

        if abs(token.last_activated.astimezone(datetime.timezone.utc) - data['request_time'].astimezone(datetime.timezone.utc)) > grace_period:
            logger.warning(f"flow control error for {token.pk=}" )
            logger.warning(f"{token.last_activated.astimezone(datetime.timezone.utc)=}" )
            logger.warning(f"{data['request_time'].astimezone(datetime.timezone.utc)=}" )
            
            # trigger automatic token deactivation
            token.is_active = False
            token.save()

            raise serializers.ValidationError({
                'request_time': ERRORS[ErrorCodes.FLOW_CONTROL_ERROR]
                })

        return data


    def validate_version(self, value):
        return value

    def validate_request_time(self, value):

        sett = AppSettingsModel.objects.get_or_create()[0]

        if not sett.validate_existing:
            return value
        
        if not sett.ticket_expiry_period:
            raise ImproperlyConfigured("ticket_expiry_period missing! Run setup_app command")
        
        if timezone.now().astimezone(datetime.timezone.utc) - value.astimezone(datetime.timezone.utc) < timedelta():
            raise serializers.ValidationError(ERRORS[ErrorCodes.REQ_TIME_FUTURE])

        if abs(timezone.now().astimezone(datetime.timezone.utc) - value.astimezone(datetime.timezone.utc)) > sett.ticket_expiry_period:
            raise serializers.ValidationError(ERRORS[ErrorCodes.TICKET_EXPIRED], 'expired')

        return value

    def validate_public_key(self, value):

        if not AppSettingsModel.objects.get_or_create()[0].validate_existing:
            return value     


        if self.context.get("claimed_pubkey"):
            if self.context.get("claimed_pubkey") != value:
                raise serializers.ValidationError(ERRORS[ErrorCodes.PUBKEYS_MISMATCH])


        token = None
        try:
            token = TokensModel.objects.get(pubkey = value)
        except ObjectDoesNotExist as exc:
                
                # if AppSettingsModel.objects.get_or_create()[0].allow_new:
                #     return value

                raise serializers.ValidationError(
                    detail=ERRORS[ErrorCodes.UNREGISTERED_TICKET],
                    code='unregistered'
                ) from exc

        if token and not token.is_active:
            raise serializers.ValidationError(
                detail=ERRORS[ErrorCodes.INACTIVE_TICKET],
                code='inactive'
            )

        return value

    # def validate_imei(self, value):

    #     # if not AppSettingsModel.objects.get_or_create()[0].validate_existing:
    #     #     return value

    #     return value

    def validate_ip(self, value):

        # if not AppSettingsModel.objects.get_or_create()[0].validate_existing:
        #     return value

        return value
    

class MainRequestSerializer(serializers.Serializer):


    version = serializers.CharField()
    request_time = serializers.DateTimeField()
    public_key = serializers.CharField()
    pin = serializers.CharField(max_length=64, min_length=64)
    ticket = TicketSerializer(required = False)
    ip = serializers.IPAddressField()



    def create(self, validated_data):

        token_exists = TokensModel.objects.filter(pubkey = validated_data['public_key']).exists()

        # this check should be redundant because of the is_valid() call, but is here just in case
        if not token_exists and not AppSettingsModel.objects.get_or_create()[0].allow_new:
            raise serializers.ValidationError(ERRORS[ErrorCodes.NEW_TKN_NOT_ALLOWED])

        if token_exists:
            token = TokensModel.objects.get(pubkey = validated_data['public_key'])
        else:
            token = TokensModel(
                pubkey = validated_data['public_key'],
                pin = PasswordHasher().hash(validated_data['pin']),
                is_active = False,
                can_reset_password = True
                )
            token.save()

        return token


    def create_ticket(self):

        token_exists = TokensModel.objects.filter(pubkey = self.validated_data['public_key']).exists()

        if not token_exists:
            raise serializers.ValidationError(ERRORS[ErrorCodes.CANNOT_CREATE_TICKET_UNREGISTERED])

        token = TokensModel.objects.get(pubkey = self.validated_data['public_key'])

        timestamp = timezone.now()

        ticket_data = {
            "version": settings.APP_VERSION,
            "request_time": timestamp,
            "public_key": self.validated_data['public_key'],
            "ip": self.context['ip'],
        }

        ticket = TicketSerializer(ticket_data)

        token.last_activated = timestamp
        token.save()

        return ticket.data

    def to_internal_value(self, data): # additional_data = None

        if not isinstance(data, dict):
            raise serializers.ValidationError({
                api_settings.NON_FIELD_ERRORS_KEY: ERRORS[ErrorCodes.TKN_DATA_NOT_DICT]
            })
        
        if set(data.keys()) != set(['token']):
            raise serializers.ValidationError({
                api_settings.NON_FIELD_ERRORS_KEY: ERRORS[ErrorCodes.INCORRECT_DICT_KEYS_TOKEN]
            })
        
        ip_from_data = self.context.get('ip')
        data = data['token']

        try:
            claimed_payload : dict = jwt.decode(data, options={"verify_signature": False})
        except DecodeError as exc:
            raise serializers.ValidationError({
                api_settings.NON_FIELD_ERRORS_KEY: ERRORS[ErrorCodes.INCORR_JWT_TOKEN]
            }) from exc

        # logger.info()
        # logger.info(type(self.get_fields()))

        # field_names = [self.get_fields().keys())

        self.context['public_key'] = claimed_payload['public_key']

        if not set(claimed_payload.keys()) == (set(self.get_fields().keys()) - {'ip'}):
            raise serializers.ValidationError({
                api_settings.NON_FIELD_ERRORS_KEY: ERRORS[ErrorCodes.INCORR_TOKEN_KEYS] + "Got {claimed_payload.keys()=}, but expected {self.fields.keys()=}"
            })
        
        app_ver = settings.APP_VERSION
        if claimed_payload['version'] != app_ver:
            raise serializers.ValidationError({"version" : ERRORS[ErrorCodes.UNSUP_APP_VERSION]})


        claimed_pubkey = claimed_payload['public_key']

        pubkey_validation_result = pubkey_validation(claimed_pubkey)

        if pubkey_validation_result:
            raise serializers.ValidationError({
                'public_key': ERRORS[ErrorCodes.PUBKEY_INCORR_FMT] + pubkey_validation_result
            })

        try:
            jwt.decode(data, claimed_pubkey, algorithms=['RS256'])
        except InvalidSignatureError as exc:
            raise serializers.ValidationError({
                api_settings.NON_FIELD_ERRORS_KEY: ERRORS[ErrorCodes.MALFORMED_JWT_SIGNATURE_TOKEN]
            }) from exc



        ticket_data = {'ticket': claimed_payload.pop('ticket')}


        claimed_payload['ip'] = ip_from_data
        validated_payload = super().to_internal_value(claimed_payload)

        # logger.warning("before2")

        if ticket_data['ticket'] and TokensModel.objects.filter(pubkey = claimed_payload['public_key']).exists():
            serializer = TicketSerializer(data = ticket_data, context = {'claimed_pubkey': claimed_payload['public_key']})
            # logger.warning("before")
            if not serializer.is_valid():
                raise serializers.ValidationError({
                    'ticket': serializer.errors
                })
            # logger.warning("after")
            validated_payload['ticket'] = serializer.validated_data


        return validated_payload

    # def to_representation(self, instance):
    #     try:
    #         ticket = create_encrypted_ticket_from_database(instance)
    #     except Exception as exc:
    #         raise serializers.ValidationError({
    #                 api_settings.NON_FIELD_ERRORS_KEY: f"unknown error in creating ticket"
    #         }) from exc
    #     return {'ticket': ticket}


    def validate(self, data: dict):

        sett = AppSettingsModel.objects.get_or_create()[0]        

        token = None
        try:
            token = TokensModel.objects.get(pubkey = data['public_key'])
        except ObjectDoesNotExist:
            pass


        if token and not data.get('ticket', None):
            raise serializers.ValidationError({
                    'ticket': ERRORS[ErrorCodes.TICKET_IS_REQUIRED]
                })
        elif not token and data.get('ticket', None):
            raise serializers.ValidationError({
                    'ticket': ERRORS[ErrorCodes.NEW_TKN_SHOULDNT_TICKETS]
                })


        if token and token.allowed_ips and sett.validate_existing:

            is_valid_ip_flag = False

            for ipaddr in token.allowed_ips.replace(' ', '').split(','):
                is_ip = True
                is_network = True
                try: ipaddress.ip_address(ipaddr)
                except ValueError: is_ip = False
                try: ipaddress.ip_network(ipaddr)
                except ValueError: is_network = False

                if is_ip:
                    if ipaddress.ip_address(data['ip']) == ipaddress.ip_address(ipaddr):
                        is_valid_ip_flag = True
                        break

                if is_network:
                    if ipaddress.ip_address(data['ip']) in ipaddress.ip_network(ipaddr):
                        is_valid_ip_flag = True
                        break

            if not is_valid_ip_flag:
                raise serializers.ValidationError({
                    'ip': ERRORS[ErrorCodes.NOT_A_VALID_IP]
                })


        if token:
            if token.can_reset_password:
                token.pin = PasswordHasher().hash(data['pin'])
                token.can_reset_password = False
                token.save()
            else:
                if sett.validate_existing:
                    ph = PasswordHasher()
                    try:
                        ph.verify(token.pin, data['pin'])
                    except argon2.exceptions.VerifyMismatchError as exc:
                        raise serializers.ValidationError({
                            'pin': ERRORS[ErrorCodes.PIN_IS_INVALID]
                        }) from exc

        return data



    def validate_version(self, value):
        # in to_internal_value, cause we want to stop processing ASAP
        pass


    def validate_request_time(self, value):
        
        # logger.info(f"{timezone.now().astimezone(datetime.timezone.utc)=}")
        # logger.info(f"{value.astimezone(datetime.timezone.utc)=}")

        if timezone.now().astimezone(datetime.timezone.utc) - value.astimezone(datetime.timezone.utc) < -timedelta(seconds=3):
            raise serializers.ValidationError(ERRORS[ErrorCodes.REQ_TIME_TOKEN_FUTURE])

        grace_period = timedelta(seconds=5)

        if abs(timezone.now().astimezone(datetime.timezone.utc) - value.astimezone(datetime.timezone.utc)) > grace_period:
            raise serializers.ValidationError(ERRORS[ErrorCodes.REQ_TOO_OLD], 'old')

        return value


    def validate_public_key(self, value):


        # logger.warning("asdf")

        token = None
        try:
            token = TokensModel.objects.get(pubkey = value)
        except ObjectDoesNotExist as exc:
            if not AppSettingsModel.objects.get_or_create()[0].allow_new:
                raise serializers.ValidationError(
                    detail=ERRORS[ErrorCodes.TOKEN_IS_UNREGISTERED],
                    code='unregistered'
                ) from exc

        if not AppSettingsModel.objects.get_or_create()[0].validate_existing:
            return value

        if token and not token.is_active:
            raise serializers.ValidationError(
                detail=ERRORS[ErrorCodes.INACTIVE_TOKEN],
                code='inactive'
            )

        return value
    

    def validate_ip(self, value):
        return value


    def validate_pin(self, value):
        return value

    pass