import os; os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dplback.settings')

import django; django.setup()


# from dplapp.utils import save_keypair_to_database


# save_keypair_to_database()

print('---')
print('---')
import jwt
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
from cryptography.fernet import Fernet

from dplapp.models import AppSettingsModel, TokensModel

# from django.utils import timezone

from datetime import timezone as builtin_tz

from argon2 import PasswordHasher


from django.conf import settings


from dplapp.serializers import TicketSerializer, MainRequestSerializer

from dplapp.utils import *

from datetime import datetime, timedelta
from datetime import timezone as builtin_tz

from django.utils import timezone

import uuid

from django.core.exceptions import ValidationError

import re

import hashlib

# def generate_keypair():
#     private_key =  ed25519.Ed25519PrivateKey.generate()
#     public_key = private_key.public_key()

#     private_bytes = private_key.private_bytes(
#                 encoding=serialization.Encoding.PEM,
#                 format=serialization.PrivateFormat.PKCS8,
#                 encryption_algorithm=serialization.NoEncryption(),
#             ).decode()

#     public_bytes = public_key.public_bytes(
#                 encoding=serialization.Encoding.PEM,
#                 format=serialization.PublicFormat.SubjectPublicKeyInfo,
#             ).decode()

#     return private_bytes, public_bytes


# def generate_encryption_cipher(key : bytes | None = None):
#     if not key:
#         encryption_key = Fernet.generate_key()
#     else:
#         encryption_key = key
#     return (Fernet(encryption_key), encryption_key)

# def jwt_encode(payload, private_key):
#     return jwt.encode(payload, private_key, algorithm="EdDSA")

# def jwt_decode(payload, public_key):
#     return jwt.decode(payload, public_key, algorithms=["EdDSA"])


# def jwt_encode_and_encrypt(payload, private_key, cipher_and_key: tuple[Fernet, bytes]):
#     encrypted_payload = cipher_and_key[0].encrypt(str(payload).encode())

#     return jwt_encode({"payload": encrypted_payload.decode()}, private_key)


# def jwt_decode_and_decrypt(payload, public_key, cipher_and_key: tuple[Fernet, bytes]):
#     decoded_jwt = jwt_decode(payload, public_key)

#     return cipher_and_key[0].decrypt(decoded_jwt["payload"].encode()).decode()


# private_key, public_key = generate_keypair()
# cipher_and_key = generate_encryption_cipher()

# # Данные, которые нужно зашифровать
# initial_payload = {"user_id": 123, "role": "admin"}

# print('---')

# print(encoded_jwt := jwt_encode_and_encrypt(initial_payload, private_key, cipher_and_key))

# print(jwt_decode_and_decrypt(encoded_jwt,public_key, cipher_and_key))



# timezone.utcoffset(datetime.now(timezone(timedelta(hours=3))).tzinfo)

# sett = AppSettingsModel.objects.get_or_create()[0]

# print(f"{sett.enforcing_mode=}")


# TOKEN_PUBLIC_KEY = """
# -----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi68WpNPQNGOD3FFjIeskG5imHYbZ/rLEnyPaqbMus4vlNY2X9nIGuvmp01lHXl3uKxP+RWLu++SxoWbnZlYh9rU4bygOUvLbH9Jduk3hWVD2oCz1NmIKdhni3Fo3JrG1uuDepGR6xEGRuR/qzxzoJ/582P5Yilpg8NJ3l3RS3MYMagDX9dLDVgluuvS1Olv879KnkAsOwsnsZmL/wk/Gr+W3fEOVegB8vXc7L5tcwIDADycOgmkYOqAlVKKmRbPfVZninnna7YZM8MGnxHPaUWoQF8O5Vf/KCivIQiNQjWQSf5AelP+t3ZGnuT7ipuaKhO3Z5p67ixvXJe4ezWhmYwIDAQAB-----END PUBLIC KEY-----
# """
# TOKEN_PUBLIC_KEY = re.sub(r'(\r\n)|\n', '', TOKEN_PUBLIC_KEY)


# tz_now_timestamp = timezone.now()

# print(f"{tz_now_timestamp=}")

# if TokensModel.objects.filter(pubkey = TOKEN_PUBLIC_KEY).exists():
#     sample_token = TokensModel.objects.get(pubkey = TOKEN_PUBLIC_KEY)
# else:
#     sample_token = TokensModel(
#         pubkey = TOKEN_PUBLIC_KEY,
#         pin = uuid.uuid4(),
#         last_activated = tz_now_timestamp,
#         # pin_salt = uuid.uuid4(),
#         allowed_ips = '243.19.198.0/24, 127.0.0.1'
#         # is_active = False
#     )

# sample_token.last_activated = datetime(2025, 3, 18, 2, 49, 12, 854362, tzinfo=builtin_tz.utc)
# sample_token.is_active = True
# sample_token.allowed_ips = '243.19.198.0/24, 127.0.0.1'
# sample_token.pin = "$argon2id$v=19$m=65536,t=3,p=4$rHqplMS4k6LTVjgmYDQWbw$vn3OUYLQzDwf5pSHgc7fjHzA2Xyp0AhVwSMPTZNr3jU"

# print(f"{sample_token.last_activated=}")

# print(f"{sample_token.pubkey=}")

# try:
#     sample_token.save()
# except ValidationError as exc:
#     raise ValidationError("") from exc # so ide would break here



# obj = {
#     "version": "v0.0.3",
#     # "request_time": timezone.now(), # - timedelta(days=7, hours=23), # + timedelta(weeks=1337),
#     # "request_time": timezone.now() - timedelta(days=6, hours=23), 
#     # "request_time": tz_now_timestamp,
#     "request_time": sample_token.last_activated,
#     "public_key": sample_token.pubkey,
#     # "imei": "imei",
#     "ip": "243.19.198.20",
# }

# ts = TicketSerializer(obj)

# ticket = ts.data

# print(ticket)

# ts = TicketSerializer(data=ticket)

# ts.is_valid()




# # print(ts.errors)

# print(ts.validated_data)


# sample_token.refresh_from_db()
# print(sample_token.is_active)


# print(sample_token.fingerprint)

# TokensModel.objects.filter().delete()

# exit()


# TokensModel.objects.all().delete()


data = {'token': 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZXJzaW9uIjoidjAuMC4zIiwicmVxdWVzdF90aW1lIjoiMjAyNS0wMy0yMVQwNzoyOTozNS42NTcyNDQrMDM6MDAiLCJwdWJsaWNfa2V5IjoiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1NSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQW0wRFVLdE5iTmtyYlNuQmNuSVZoc2pwZnFvNzdEZVk5dDNpOUZ6UmEvUDI5U3BOSTdINE5uL3VnNHNjY3JvaXIrU0pEZVNnRHdnOXBSUjljcld4UGRPa1NPa3lSc2NucVZvVjBtQ3hVand3Y2owWWgxa29uZjNrWW1WUFNzUnE2dkd5czAzYk5US3hQOXNZWWthdmozM2V5U0xvaWFBbTU1YjMrcEZyODZEdkJ6VkxJdWdGK1NqVlEzWExSMXBaZTJnc1VOejNDK1VIUkRPVERMZU5naTRaZ1VLUXJKU1dMcjZJVkpIYmJhSjlvOFc2QXlpbzl6NWxUdHJBYWZHN2s2eUtHQlBVckVxeVp4cnljZWIyNXF6azI0bC9FK3krOXl2QlNiLzZZdlZSMUVrb2NRVi9KZGRuN0xEcmhOYkEweVVHR1F1MGRFQ0hCekQ1enFwTXJId0lEQVFBQi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLSIsInBpbiI6IjQzY2UxMWMyNDM1OTYyZWEwYWEyNDA4ZmZlMDYyNGFlNGE5YmJlNDQ4NzkxYWRkNjZmMzUyZjdkM2I4ZjBkNmYiLCJ0aWNrZXQiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SWtwWFZDSjkuZXlKd1lYbHNiMkZrSWpvaVowRkJRVUZCUW00elQycG5NVEZLUkVwZll6QmZWRFJsVlhKT1lVNXZTMmxCTXkxaFExVTRMVlZPZGtzdFNUUXpSbTltTFVkRlNXRlJVSEJzVnkwMVUwbHpiak01YVZONVFWVmhhRFpKVEdvME5VSm9TV2RNTFUwd04xRk1WVWczUkhCR01tSm5ibWh0ZUZGR1kycHVNMWh5U0hSSFJsQlJRVTFaVjNKUGNFdG9hRUp2WWpWalptaFRYMTl3Y21GRGRGaFlXR2xQY2w5Q2VXbzJURTVDY2pGWVZERkJja1pNWDFadmNGWjRXSGR4TlcxWVVUaGpTM1ZHWjNVMlJGVTVlVFl4V2xvMWRsUlVhMlJWWkZVeWR6WmpaVUZPTUdOemNYbFNOR2xWWmpaU1RFY3RSVzlVVTNWeE1tdDNNbXQ0VGtobU0ybE5SUzFCUkd4S1MyODRVM0ZNV0dVellVVkJNa3RuY1c5R09VWmtaMFZZZGs1eVRESjJaRVJGY0hsbVpXdENVRkZvUTJwUlR6ZHZWMEV6TlZGVmNuVldkMTl0V2tWUFpWUnVPR3RzVUROME1FVjJlbnBaUmxSMWFGbzVWVnBQT0RCeGRVbzVaVnB3WkhWUlVsUkRaMlZoTFRCNmVUZDNZelkzYzA0NFdHSTNZbVZXZEU1UWVDMWZZUzFrWm5WQlFXZGpiSFp4V1hoWFpGWXlkMk5mYWxKS1FWVldSWFpHU2xFd1dtcHNlWEJTVTJVNFN6UXhjWE5xV0c1V1YwUndNR3htVVZSc05YQnlha0ppWlZNMGVtTjBaVVZTU0hKa1lrSTBOMHBCYzJVeU1YbGlVbXBuTVZodmRqSldUakp1V1VWRVkwd3phR2hyT1ZSUFVGQjBVbVpyV1hReWNFNUViVzFRT0VaM1JGZGZkVFZyWW5Kb2MxaDNPWFZwWDJKTGEyNUlUVFJ6U25CcVNVZFNiRkZxZGtoWVJrODNYMUJNYlRaa1gyVjFUR1ZSV0ZneGRqTm9iRlpuYmpkYWJETmpNMWRZVTFGMlZYVlZlRjl3U1Y5SFVtVkdOSGxrU1ROUVFtMVJWSFpIUW05VkxXbFJlbEUwTFVGSGMzUlBRVTR6VWsxemIydHdlREp2YVVKcldrUlNkakF3T0dGblprNTVSbXcwYWtveFh6bFFNV0Z4Y2xCUlJETjVaV1JPYmpGRlYzTjJObEpmY0VkV1IyWjJXaTE0YkhrM1NrMTNiRXd3TlhwemRIVlhkMmhOVVc5elVqQmxSbTVZY2pRM1JtaFNVVkZsWmxaWFluUlFjMHRQZDBaeGVqUndSMUpQYjE5UGExSnNNQzFzWW1Ob1pYbDNYemw0Um5OVlZWaGpXRUkxUTFWSFFYRlNkR3hzUVhwd1ZrZFpiRWhET1cxdWRHVm1lRkJMVjFZMVFsZG1aVWxQVW14VlkzRjNSbnBaU1c5c1FuaGxValZvVUVWc1dGUmlRVkpHWmxWRFYwWm1TV2wyZGtSNVEwdFNTSGxoVTBKaE9HNVVNVVJ2YjNSRldFOVZVVXQxWVZOVE0wdzFkbVpKVGw5R1pIaFBNamhUWlhGTVQzY3piVk5wTWxKT1h6bHVhMG8zTFUwaWZRLnRMNWNmOUNQSkdQa2duQVhvWU1jS3I3bVJ6TXkxMkgtTUFmOWhuNG5SNUJ0VVpUeW1BV29mbFFNUnRURl9wLVdUS25EbGRNV3NTM3JMUVQzNHZLRkFRIn0.YyGS7m2uH5pnt0gENjCguD1UOeFN9WBR_h4qYJoLDxYh_rr3T6X5HamOyAXkKMKItu-I51XzXxIfiuZ4joOcDEjq7OvYKYkB9cCG1QkK6C_Dts8z5iwLNdsYc63ICNYER3TAOAVIJCcWYpS7VBGm_nRh8M7EtQC-wQrHtry0XO7lOzeMB5M4Wnvj9H8WcG8_4K9hFdFnczDmld6q3WcA54KhfHf5Csg_cX_IF0Y1qWzqSDxVl3ACHce9S4a8UaP528cHthVctP0DEeYVZCuynU2VakR7auvOfVezuhfTGSPQTMNQI9tQ4mMlJ9uQsNQ-U8091fgBsnr8w1N3tFlAow'}

ts = MainRequestSerializer(data = data, context = {'ip': '192.168.1.67'})

print(ts.is_valid())
print(ts.errors)


ts2 = TicketSerializer(data = {'ticket': "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJwYXlsb2FkIjoiZ0FBQUFBQm4zT2pnMTFKREpfYzBfVDRlVXJOYU5vS2lBMy1hQ1U4LVVOdkstSTQzRm9mLUdFSWFRUHBsVy01U0lzbjM5aVN5QVVhaDZJTGo0NUJoSWdMLU0wN1FMVUg3RHBGMmJnbmhteFFGY2puM1hySHRHRlBRQU1ZV3JPcEtoaEJvYjVjZmhTX19wcmFDdFhYWGlPcl9CeWo2TE5CcjFYVDFBckZMX1ZvcFZ4WHdxNW1YUThjS3VGZ3U2RFU5eTYxWlo1dlRUa2RVZFUydzZjZUFOMGNzcXlSNGlVZjZSTEctRW9UU3VxMmt3Mmt4TkhmM2lNRS1BRGxKS284U3FMWGUzYUVBMktncW9GOUZkZ0VYdk5yTDJ2ZERFcHlmZWtCUFFoQ2pRTzdvV0EzNVFVcnVWd19tWkVPZVRuOGtsUDN0MEV2enpZRlR1aFo5VVpPODBxdUo5ZVpwZHVRUlRDZ2VhLTB6eTd3YzY3c044WGI3YmVWdE5QeC1fYS1kZnVBQWdjbHZxWXhXZFYyd2NfalJKQVVWRXZGSlEwWmpseXBSU2U4SzQxcXNqWG5WV0RwMGxmUVRsNXByakJiZVM0emN0ZUVSSHJkYkI0N0pBc2UyMXliUmpnMVhvdjJWTjJuWUVEY0wzaGhrOVRPUFB0UmZrWXQycE5EbW1QOEZ3RFdfdTVrYnJoc1h3OXVpX2JLa25ITTRzSnBqSUdSbFFqdkhYRk83X1BMbTZkX2V1TGVRWFgxdjNobFZnbjdabDNjM1dYU1F2VXVVeF9wSV9HUmVGNHlkSTNQQm1RVHZHQm9VLWlRelE0LUFHc3RPQU4zUk1zb2tweDJvaUJrWkRSdjAwOGFnZk55Rmw0akoxXzlQMWFxclBRRDN5ZWRObjFFV3N2NlJfcEdWR2Z2Wi14bHk3Sk13bEwwNXpzdHVXd2hNUW9zUjBlRm5YcjQ3RmhSUVFlZlZXYnRQc0tPd0ZxejRwR1JPb19Pa1JsMC1sYmNoZXl3Xzl4RnNVVVhjWEI1Q1VHQXFSdGxsQXpwVkdZbEhDOW1udGVmeFBLV1Y1QldmZUlPUmxVY3F3RnpZSW9sQnhlUjVoUEVsWFRiQVJGZlVDV0ZmSWl2dkR5Q0tSSHlhU0JhOG5UMURvb3RFWE9VUUt1YVNTM0w1dmZJTl9GZHhPMjhTZXFMT3czbVNpMlJOXzlua0o3LU0ifQ.tL5cf9CPJGPkgnAXoYMcKr7mRzMy12H-MAf9hn4nR5BtUZTymAWoflQMRtTF_p-WTKnDldMWsS3rLQT34vKFAQ"})

print(ts2.is_valid())
print(ts2.errors)

# print(decrypt_ticket_from_database("eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJwYXlsb2FkIjoiZ0FBQUFBQm4zT2pnMTFKREpfYzBfVDRlVXJOYU5vS2lBMy1hQ1U4LVVOdkstSTQzRm9mLUdFSWFRUHBsVy01U0lzbjM5aVN5QVVhaDZJTGo0NUJoSWdMLU0wN1FMVUg3RHBGMmJnbmhteFFGY2puM1hySHRHRlBRQU1ZV3JPcEtoaEJvYjVjZmhTX19wcmFDdFhYWGlPcl9CeWo2TE5CcjFYVDFBckZMX1ZvcFZ4WHdxNW1YUThjS3VGZ3U2RFU5eTYxWlo1dlRUa2RVZFUydzZjZUFOMGNzcXlSNGlVZjZSTEctRW9UU3VxMmt3Mmt4TkhmM2lNRS1BRGxKS284U3FMWGUzYUVBMktncW9GOUZkZ0VYdk5yTDJ2ZERFcHlmZWtCUFFoQ2pRTzdvV0EzNVFVcnVWd19tWkVPZVRuOGtsUDN0MEV2enpZRlR1aFo5VVpPODBxdUo5ZVpwZHVRUlRDZ2VhLTB6eTd3YzY3c044WGI3YmVWdE5QeC1fYS1kZnVBQWdjbHZxWXhXZFYyd2NfalJKQVVWRXZGSlEwWmpseXBSU2U4SzQxcXNqWG5WV0RwMGxmUVRsNXByakJiZVM0emN0ZUVSSHJkYkI0N0pBc2UyMXliUmpnMVhvdjJWTjJuWUVEY0wzaGhrOVRPUFB0UmZrWXQycE5EbW1QOEZ3RFdfdTVrYnJoc1h3OXVpX2JLa25ITTRzSnBqSUdSbFFqdkhYRk83X1BMbTZkX2V1TGVRWFgxdjNobFZnbjdabDNjM1dYU1F2VXVVeF9wSV9HUmVGNHlkSTNQQm1RVHZHQm9VLWlRelE0LUFHc3RPQU4zUk1zb2tweDJvaUJrWkRSdjAwOGFnZk55Rmw0akoxXzlQMWFxclBRRDN5ZWRObjFFV3N2NlJfcEdWR2Z2Wi14bHk3Sk13bEwwNXpzdHVXd2hNUW9zUjBlRm5YcjQ3RmhSUVFlZlZXYnRQc0tPd0ZxejRwR1JPb19Pa1JsMC1sYmNoZXl3Xzl4RnNVVVhjWEI1Q1VHQXFSdGxsQXpwVkdZbEhDOW1udGVmeFBLV1Y1QldmZUlPUmxVY3F3RnpZSW9sQnhlUjVoUEVsWFRiQVJGZlVDV0ZmSWl2dkR5Q0tSSHlhU0JhOG5UMURvb3RFWE9VUUt1YVNTM0w1dmZJTl9GZHhPMjhTZXFMT3czbVNpMlJOXzlua0o3LU0ifQ.tL5cf9CPJGPkgnAXoYMcKr7mRzMy12H-MAf9hn4nR5BtUZTymAWoflQMRtTF_p-WTKnDldMWsS3rLQT34vKFAQ"))


exit()


# --- Эмуляция клиента ---

private_key =  rsa.generate_private_key(key_size=2048, public_exponent=65537)
public_key = private_key.public_key()

private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
private_bytes = re.sub(r'(\r\n)|\n', '', private_bytes)


public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
public_bytes = re.sub(r'(\r\n)|\n', '', public_bytes)

fingerprint = ' '.join(f'{byte:02X}' for byte in hashlib.sha256(public_bytes.encode('utf-8')).digest()[:6])


jwt_dict = {
    "version": "v0.0.3",
    "request_time": timezone.now().isoformat(),
    "public_key": public_bytes,
    "pin": hashlib.sha256(f"1234567890{fingerprint}".encode('utf-8')).hexdigest(),
    "ticket": ""
}

tkn = jwt.encode(jwt_dict, private_key, algorithm="RS256")

# --- / Эмуляция клиента ---



# sample_token = f"""
# Отпечаток токена: {fingerprint}


# {tkn}


# {public_bytes}
# """

# sample_token = sample_token.split('\n\n')[1]
# sample_token = re.sub(r'(\r\n)|\n', '', sample_token)


# --- Начало обработки запроса от клиента ---

req_ip = "243.19.198.20"

req_obj = {
    "token": tkn
}

request_serializer = MainRequestSerializer(data = req_obj, context = {'ip': req_ip})

if not request_serializer.is_valid():
    print(request_serializer.errors)
    exit()

# print(request_serializer.is_valid())

# print(request_serializer.initial_data)

# print(request_serializer.validated_data)

# import code
# code.interact(local=locals())

# --- Создание тикета в БД (рассматриваем сценарий, когда тикета ещё нет) --- 

token = request_serializer.save()

# --- Создание тикета для этого токена ---

ticket_data = request_serializer.create_ticket()

# print(ticket_data)

from dplapp.models import HistoryModel
from dplapp.serializers import HistorySerializer

HistoryModel.objects.create(
    token = token,
    ip = req_ip,
    result = "",
    msg = "SUCCESS",
)

history_queryset = HistoryModel.objects.filter(token = token).order_by("datetime")[:5]

history_items = HistorySerializer(history_queryset, many = True)

ticket_data.update({'history': history_items.data})

print(ticket_data)

exit()

# этот токен посылается в ответ


# --- Попытка повторного запроса с уже имеющимся токеном ---

# --- Повторная эмуляция клиента ---

# jwt_2_dict = {
#     "version": "v0.0.3",
#     "request_time": timezone.now().isoformat(),
#     "public_key": public_bytes,
#     "pin": hashlib.sha256(f"1234567890{fingerprint}".encode('utf-8')).hexdigest(),
#     "ticket": ts.data['ticket']
# }

# tkn2 = jwt.encode(jwt_2_dict, private_key, algorithm="RS256")

# --- / Повторная эмуляция клиента ---



# --- Начало обработки запроса от клиента ---

# req_ip = "243.19.198.20"

# req_obj = {
#     "ip": req_ip,
#     "token": tkn2,
# }

# request_serializer = MainRequestSerializer(data = req_obj)

# print(request_serializer.is_valid())
# print(request_serializer.errors)

# print(request_serializer.validated_data)


# --- Сравнение с тикетом в БД (рассматриваем сценарий, когда такой тикет уже есть) --- 

# new_tz_now_timestamp = timezone.now()

# new_token = TokensModel.objects.get(pubkey = request_serializer.validated_data['public_key'])

# new_token.last_activated = new_tz_now_timestamp

# new_token.save()


# --- Создание тикета для этого токена ---

# obj = {
#     "version": settings.APP_VERSION,
#     "request_time": new_tz_now_timestamp,
#     "public_key": request_serializer.validated_data['public_key'],
#     "ip": req_ip,
# }

# ts = TicketSerializer(obj)

# print(ts.data)

# этот токен посылается в ответ во второй раз


# --- Попытка повторного запроса с тем же токеном






# import code
# code.interact(local=locals())




# sample_token ="""
# Отпечаток токена: DD 88 B7 39 43 9C


# eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZXJzaW9uIjoidjAuMC4zIiwicmVxdWVzdF90aW1lIjoiMjAyNS0wMy0xOFQwNzowNjo1OS42Mzc3NjIrMDM6MDAiLCJwdWJsaWNfa2V5IjoiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1NSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQWk2OFdwTlBRTkdPRDNGRmpJZXNrRzVpbUhZYlovckxFbnlQYXFiTXVzNHZsTlkyWDluSUd1dm1wMDFsSFhsM3VLeFArUldMdSsrU3hvV2JuWmxZaDlyVTRieWdPVXZMYkg5SmR1azNoV1ZEMm9DejFObUlLZGhuaTNGbzNKckcxdXVEZXBHUjZ4RUdSdVIvcXp4em9KLzU4MlA1WWlscGc4TkozbDNSUzNNWU1hZ0RYOWRMRFZnbHV1dlMxT2x2ODc5S25rQXNPd3Nuc1ptTC93ay9HcitXM2ZFT1ZlZ0I4dlhjN0w1dGN3SURBRHljT2dta1lPcUFsVktLbVJiUGZWWm5pbm5uYTdZWk04TUdueEhQYVVXb1FGOE81VmYvS0NpdklRaU5RaldRU2Y1QWVsUCt0M1pHbnVUN2lwdWFLaE8zWjVwNjdpeHZYSmU0ZXpXaG1Zd0lEQVFBQi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLSIsInBpbiI6IjNjMTZkYTU3MWUwOTA1OTZiMGFjMWJhMTNjNzFmZDQ5ZTVlYTIzMjFkNzFkOWRiNGNmM2JmNDgxNWUxOTg2N2YiLCJ0aWNrZXQiOiIifQ.SZ5IU29_DBRLYnVbyHncYwVu-TdDWmU5PU-D_irsecpKDgiyLti-j7RoXwtj29JAtlSzMunaNiWcbvz-x1A4jdJQjEHcY3ABkGu5MXXnm8u2M3RIL9MNcrSGNJkm7C2eylk2-6iDE4I2XmhroxEdmzJiI2BJdhkVYFm7bCTG1mSUz6ngs9--kR8vZwy-HM8GwCx_0D0D7zUfMsgzxg4ax-rcE5p3eJ8NbWTz8UXzzJATVMNAsHGf06ps9ad4qc5AmI7Cq8Wl154BowWTR1Wi1ReJe0wPedzYm2wGa58wiVmzAfEXouDOIoBed31uth7LfYMKRy3LHsake7yMMR2baw


# -----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi68WpNPQNGOD3FFjIeskG5imHYbZ/rLEnyPaqbMus4vlNY2X9nIGuvmp01lHXl3uKxP+RWLu++SxoWbnZlYh9rU4bygOUvLbH9Jduk3hWVD2oCz1NmIKdhni3Fo3JrG1uuDepGR6xEGRuR/qzxzoJ/582P5Yilpg8NJ3l3RS3MYMagDX9dLDVgluuvS1Olv879KnkAsOwsnsZmL/wk/Gr+W3fEOVegB8vXc7L5tcwIDADycOgmkYOqAlVKKmRbPfVZninnna7YZM8MGnxHPaUWoQF8O5Vf/KCivIQiNQjWQSf5AelP+t3ZGnuT7ipuaKhO3Z5p67ixvXJe4ezWhmYwIDAQAB-----END PUBLIC KEY-----
# """       





# print(request_serializer.validated_data)


# import code
# code.interact(local=locals())