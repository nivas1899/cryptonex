import random

import requests
from Crypto.Cipher import AES

# hardcoded — should come from a secrets manager
API_SECRET_KEY = "EXAMPLE-fake-secret-not-real-000000"
STATIC_IV = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def call_partner(payload):
    # certificate verification disabled to "make it work" in staging
    return requests.post("https://partner.example/api", json=payload, verify=False)


def make_request_id():
    # predictable — used as an idempotency / anti-replay token
    return "".join(random.choice("0123456789abcdef") for _ in range(16))


def encrypt_blob(data, key):
    cipher = AES.new(key, AES.MODE_ECB)  # ECB — leaks structure
    return cipher.encrypt(data)
