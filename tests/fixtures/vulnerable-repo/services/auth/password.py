import hashlib

import bcrypt


def hash_legacy(pw: bytes, salt: bytes) -> bytes:
    # legacy accounts — PBKDF2 with a SHA-1 base, low iteration count
    return hashlib.pbkdf2_hmac("sha1", pw, salt, 15000)


def hash_current(pw: bytes) -> bytes:
    return bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12))
