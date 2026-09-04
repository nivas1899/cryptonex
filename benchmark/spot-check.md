# ECDAT precision spot-check

Mark each row **TP** (true positive) or **FP** (false positive) by hand, then compute precision = TP / (TP + FP).

| # | kind | repo | what | detail | conf/sev | location | TP/FP |
|--:|---|---|---|---|---|---|:--:|
| 1 | asset | node-jsonwebtoken | DSA | DSA | confirmed | `test/dsa-public.pem` |  |
| 2 | asset | pyjwt | HMAC-SHA-256 | HMAC | high | `tests/test_api_jwt.py:449` |  |
| 3 | asset | cryptography | 3DES | 3DES | medium | `tests/hazmat/primitives/decrepit/test_algorithms.py:91` |  |
| 4 | asset | cryptography | X25519 | ECC | high | `tests/hazmat/primitives/test_x25519.py:201` |  |
| 5 | asset | cryptography | X25519 | ECC | high | `tests/hazmat/primitives/test_hpke.py:563` |  |
| 6 | asset | node-jsonwebtoken | HMAC-SHA-256 | HMAC | high | `test/jwt.malicious.tests.js:9` |  |
| 7 | asset | golang-jwt | RSA | RSA | confirmed | `test/privateSecure.pem` |  |
| 8 | asset | paramiko | X25519 | ECC | high | `tests/test_kex.py:142` |  |
| 9 | asset | cryptography | AES | AES | high | `tests/hazmat/primitives/test_aead.py:615` |  |
| 10 | asset | pyjwt | HMAC-SHA-256 | HMAC | high | `tests/test_api_jwt.py:567` |  |
| 11 | asset | pyjwt | HMAC-SHA-256 | HMAC | high | `tests/test_api_jwt.py:529` |  |
| 12 | asset | paramiko | AES | AES | medium | `tests/test_packetizer.py:80` |  |
| 13 | asset | cryptography | X25519 | ECC | high | `tests/hazmat/primitives/test_hpke.py:248` |  |
| 14 | asset | cryptography | X25519 | ECC | high | `tests/hazmat/primitives/test_mldsa.py:417` |  |
| 15 | asset | pyjwt | HMAC-SHA-256 | HMAC | high | `tests/test_api_jwt.py:462` |  |
| 16 | asset | cryptography | X25519 | ECC | high | `tests/hazmat/primitives/test_hpke.py:227` |  |
| 17 | asset | cryptography | AES | AES | high | `tests/bench/test_aead.py:50` |  |
| 18 | asset | cryptography | X25519 | ECC | high | `tests/hazmat/primitives/test_hpke.py:493` |  |
| 19 | asset | cryptography | Argon2id | Argon2 | medium | `src/cryptography/hazmat/primitives/kdf/argon2.py:17` |  |
| 20 | asset | cryptography | ECDSA | ECC | medium | `tests/hazmat/primitives/test_ec.py:643` |  |
| 21 | asset | pyjwt | RSA | RSA | high | `tests/test_api_jwt.py:370` |  |
| 22 | asset | cryptography | Ed25519 | ECC | high | `src/cryptography/hazmat/primitives/serialization/pkcs12.py:38` |  |
| 23 | asset | cryptography | AES | AES | high | `tests/hazmat/primitives/test_aead.py:630` |  |
| 24 | asset | cryptography | AES-128-CBC (Fernet) | AES | medium | `tests/test_fernet.py:191` |  |
| 25 | asset | cryptography | RC4 | RC4 | high | `tests/hazmat/primitives/test_cmac.py:122` |  |
