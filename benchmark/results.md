# ECDAT benchmark — real open-source repositories

_7 repositories scanned._

Assets / findings columns show **production (test-path)**. Grade is on production assets only.

| repo | what it is | files | assets | findings | vuln | broken | grade | time |
|---|---|--:|--:|--:|--:|--:|:--:|--:|
| `pyjwt` | JWT — signing / alg handling | 122 | 1 (12) | 2 (16) | 1 | 0 | A | 0.5s |
| `itsdangerous` | Flask signing helpers | 79 | 1 (0) | 0 (2) | 0 | 1 | B | 0.1s |
| `python-jose` | JOSE / JWT — had alg-confusion CVEs | 96 | 9 (2) | 0 (11) | 5 | 0 | A | 0.3s |
| `paramiko` | SSH — keys, KEX, ciphers | 225 | 5 (20) | 4 (13) | 4 | 0 | A | 1.1s |
| `golang-jwt` | Go JWT (successor to dgrijalva) | 106 | 3 (11) | 5 (1) | 3 | 0 | A | 0.2s |
| `node-jsonwebtoken` | Node JWT | 113 | 0 (31) | 2 (6) | 0 | 0 | A | 0.2s |
| `cryptography` | the reference Python crypto library | 3076 | 21 (10) | 31 (98) | 9 | 4 | A | 4.5s |

## Algorithm families detected per repo

- **pyjwt**: ECC, HMAC, RSA
- **itsdangerous**: SHA-1
- **python-jose**: AES, ECC, HMAC, RC4, RSA, cryptography, ecdsa, pycryptodome
- **paramiko**: AES, ECC, RSA, bcrypt
- **golang-jwt**: DSA, ECC, RSA
- **node-jsonwebtoken**: DSA, ECC, HMAC, RSA
- **cryptography**: 3DES, AES, Argon2, ChaCha20, DES, DH, DSA, ECC
