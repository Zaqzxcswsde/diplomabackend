# file for some helper functions 

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import serialization

from dplapp.models import AppSettingsModel

import sys


import jwt
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import jwt
from cryptography.fernet import Fernet


from jwt.exceptions import InvalidSignatureError, DecodeError

from django.core.exceptions import ImproperlyConfigured

import pickle

import base64

import re
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


import logging
# logFormatter = logging.Formatter("%(asctime)s [%(levelname)-5.5s]  %(message)s")
logger = logging.getLogger()
# consoleHandler = logging.StreamHandler()
# consoleHandler.setFormatter(logFormatter)
# logger.addHandler(consoleHandler)
# logger.setLevel(logging.DEBUG)

from datetime import timedelta
import uuid

def setup_app_logic(override=False):
    save_keypair_to_database(override)
    save_encryption_key_to_database(override)

    sett = AppSettingsModel.objects.get_or_create()[0]

    default_values = {
        "ticket_expiry_period": lambda: timedelta(days=7),
        "enforcing_mode":       lambda: sett.ON,
        "activity_period":      lambda: timedelta(seconds=5),
        "admin_panel_token":    lambda: uuid.uuid4()
    }

    for attr_name, def_value in default_values.items():
        if override or not getattr(sett, attr_name):
            setattr(sett, attr_name, def_value())
            logger.info(f"Changed {attr_name}")
        else:
            logger.info(f"Not changing {attr_name}")

    sett.save()



def _generate_keypair():
    private_key =  ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode()

    public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()

    return private_bytes, public_bytes


def save_keypair_to_database(override = False):

    sett = AppSettingsModel.objects.get_or_create()[0]

    if sett.private_key: # if public_key is present without private_key, override anyways
        if not override:
            logger.info("Not changing exitsting keys")
            return

    private_bytes, public_bytes = _generate_keypair()

    sett.private_key = private_bytes
    sett.public_key = public_bytes
    logger.info("Saved keys to database")

    sett.save()


def _generate_encryption_cipher(key : bytes | None = None):
    if not key:
        encryption_key = Fernet.generate_key()
    else:
        encryption_key = key
    return (Fernet(encryption_key), encryption_key)


def save_encryption_key_to_database(override = False):

    sett = AppSettingsModel.objects.get_or_create()[0]

    if sett.ticket_encryption_key:
        if not override:
            logger.info(f"Not changing exitsting encryption key")
            return

    encryption_key = _generate_encryption_cipher()[1]

    sett.ticket_encryption_key = encryption_key
    logger.info("Saved encryption key to database")

    sett.save()


def _jwt_encode(payload, private_key):
    return jwt.encode(payload, private_key, algorithm="EdDSA")


def _jwt_decode(payload, public_key):
    return jwt.decode(payload, public_key, algorithms=["EdDSA"])


def _jwt_payload_encrypt(payload, encryption_key: bytes):

    cipher = _generate_encryption_cipher(encryption_key)

    pickled_data = pickle.dumps(payload)

    # base64_bytes = base64.b64encode(pickled_data)

    encrypted_payload = cipher[0].encrypt(pickled_data)

    return {"payload": encrypted_payload.decode()}


def _jwt_payload_decrypt(payload: dict[str, str], encryption_key: bytes):

    cipher = _generate_encryption_cipher(encryption_key)

    payload_bytes : bytes = payload["payload"].encode()

    decrypted_payload = cipher[0].decrypt(payload_bytes)

    obj = pickle.loads(decrypted_payload)

    return obj


def create_jwt_token_from_database(payload : dict):

    if not isinstance(payload, dict):
        raise TypeError("Expecting a dict object, as JWT only supports JSON objects as payloads.")

    sett = AppSettingsModel.objects.get_or_create()[0]

    private_key, _ = sett.private_key, sett.public_key
    
    if not private_key:
        raise ImproperlyConfigured("private_key not configured, run setup commands from cli!")

    encoded_token = _jwt_encode(payload, private_key)

    return encoded_token


def verify_jwt_token_from_database(payload: str):

    sett = AppSettingsModel.objects.get_or_create()[0]

    _, public_key = sett.private_key, sett.public_key

    if not public_key:
        raise ImproperlyConfigured("public_key not configured, run setup commands from cli!")

    # try:
    decoded_token = _jwt_decode(payload, public_key)
    # except InvalidSignatureError as exc:
    #     decoded_token = None

    return decoded_token  


def create_encrypted_ticket_from_database(payload):

    sett = AppSettingsModel.objects.get_or_create()[0]

    ticket_encryption_key = sett.ticket_encryption_key

    if not ticket_encryption_key:
        raise ImproperlyConfigured("ticket_encryption_key not configured, run setup commands from cli!")

    encrypted_payload = _jwt_payload_encrypt(payload, ticket_encryption_key)

    token = create_jwt_token_from_database(encrypted_payload)

    return token

def decrypt_ticket_from_database(payload: str):

    # try:
    verified_token_payload = verify_jwt_token_from_database(payload)
    # except DecodeError:
    #     raise DecodeError 

    if not verified_token_payload:
        return None # in case verification failed

    sett = AppSettingsModel.objects.get_or_create()[0]

    ticket_encryption_key = sett.ticket_encryption_key

    if not ticket_encryption_key:
        raise ImproperlyConfigured("ticket_encryption_key not configured, run setup commands from cli!")
    
    decrypted_payload = _jwt_payload_decrypt(verified_token_payload, ticket_encryption_key)

    return decrypted_payload



def pubkey_validation(value: str):
    """Returns None if no errors were found, str containing error text otherwise"""

    if not value or not isinstance(value, str):
        return "pubkey should be string"

    if not (value.startswith("-----BEGIN PUBLIC KEY-----") and value.strip().endswith("-----END PUBLIC KEY-----")):
        return "malformed public key headers"

    pem_regex = r'^-----BEGIN PUBLIC KEY-----([A-Za-z0-9+\/=]+)-----END PUBLIC KEY-----$'
    if not re.search(pem_regex, value):
        return "malformed public key structure"

    try:
        pubkey = serialization.load_pem_public_key(value.encode('utf-8'))
    except Exception as exc:
        return "malformed public key"
    
    if not isinstance(pubkey, RSAPublicKey):
        return "not an RSA public key"

    if pubkey.key_size != 2048:
        return "unexpected RSA keysize, did the app update?"
    
    return None