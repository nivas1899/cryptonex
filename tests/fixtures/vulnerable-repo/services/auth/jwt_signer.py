import jwt

PRIVATE_KEY = open("/etc/keys/jwt.pem").read()


def issue_token(payload: dict) -> str:
    # RS256 — RSA-2048 signature
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")


def verify(token: str) -> dict:
    return jwt.decode(token, PRIVATE_KEY, algorithms=["RS256"])
