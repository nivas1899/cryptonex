from __future__ import annotations

import hashlib
from collections.abc import Iterator
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ecdat.domain.enums import AssetType, Confidence, Primitive
from ecdat.domain.models import AlgorithmParameters, Evidence, RawFinding
from ecdat.scanners.base import Scanner, ScanContext, walk_files

_CERT_EXT = {".pem", ".crt", ".cer", ".der", ".p7b", ".key", ".pub", ".p12", ".pfx"}


class CertificateScanner(Scanner):
    name = "certificate"

    def scan(self, ctx: ScanContext) -> Iterator[RawFinding]:
        for path in walk_files(ctx):
            if path.suffix.lower() not in _CERT_EXT:
                continue
            try:
                data = path.read_bytes()
            except OSError:
                continue
            ctx.mark(path)
            rel = ctx.rel(path)
            yield from _from_bytes(data, rel)


def _pub_params(pub) -> tuple[str, AlgorithmParameters, str]:
    if isinstance(pub, rsa.RSAPublicKey):
        return "rsa", AlgorithmParameters(key_size=pub.key_size), "signature"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "ecdsa", AlgorithmParameters(curve=pub.curve.name), "signature"
    if isinstance(pub, dsa.DSAPublicKey):
        return "dsa", AlgorithmParameters(key_size=pub.key_size), "signature"
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "ed25519", AlgorithmParameters(curve="Ed25519"), "signature"
    if isinstance(pub, ed448.Ed448PublicKey):
        return "ed448", AlgorithmParameters(curve="Ed448"), "signature"
    return "unknown", AlgorithmParameters(), "other"


def _fingerprint(pub) -> str:
    try:
        spki = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return "sha256:" + hashlib.sha256(spki).hexdigest()[:24]
    except Exception:
        return "sha256:unknown"


def _from_bytes(data: bytes, rel: str) -> Iterator[RawFinding]:
    certs: list[x509.Certificate] = []
    # PEM may contain multiple blocks
    if b"-----BEGIN CERTIFICATE-----" in data:
        blocks = data.split(b"-----END CERTIFICATE-----")
        for b in blocks:
            if b"-----BEGIN CERTIFICATE-----" not in b:
                continue
            pem = b.split(b"-----BEGIN CERTIFICATE-----")[1]
            pem = b"-----BEGIN CERTIFICATE-----" + pem + b"-----END CERTIFICATE-----\n"
            try:
                certs.append(x509.load_pem_x509_certificate(pem))
            except Exception:
                pass
    else:
        for loader in (x509.load_der_x509_certificate, x509.load_pem_x509_certificate):
            try:
                certs.append(loader(data))
                break
            except Exception:
                continue

    for cert in certs:
        pub = cert.public_key()
        fam, params, prim = _pub_params(pub)
        now = datetime.now(timezone.utc)
        try:
            not_after = cert.not_valid_after_utc
        except AttributeError:  # older cryptography
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        expired = not_after < now
        try:
            subject = cert.subject.rfc4514_string()
        except Exception:
            subject = "?"
        is_ca = False
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            is_ca = bool(bc.ca)
        except Exception:
            pass
        snippet = (
            f"subject={subject} | key={fam} {params.key_size or params.curve or ''} "
            f"| notAfter={not_after.date()}"
            + (" | EXPIRED" if expired else "")
            + (" | CA" if is_ca else "")
        )
        params.extra["expired"] = "true" if expired else "false"
        params.extra["ca"] = "true" if is_ca else "false"
        params.extra["subject"] = subject[:120]
        yield RawFinding(
            scanner="certificate",
            asset_type=AssetType.CERTIFICATE,
            raw_name=fam,
            primitive_hint=Primitive(prim) if prim in Primitive._value2member_map_ else None,
            family_hint=None,
            parameters=params,
            external_facing=True,
            evidence=Evidence(kind="certificate", locator=rel, snippet=snippet),
            confidence=Confidence.CONFIRMED,
        )

    # bare public keys
    if not certs and (b"-----BEGIN PUBLIC KEY-----" in data or b"-----BEGIN RSA PUBLIC KEY-----" in data):
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_public_key

            pub = load_pem_public_key(data)
            fam, params, _ = _pub_params(pub)
            params.extra["fingerprint"] = _fingerprint(pub)
            yield RawFinding(
                scanner="certificate",
                asset_type=AssetType.KEY,
                raw_name=fam,
                parameters=params,
                evidence=Evidence(kind="key", locator=rel, snippet=f"public key {fam} {params.extra['fingerprint']}"),
                confidence=Confidence.CONFIRMED,
            )
        except Exception:
            pass

    # private key present — record metadata only, never the material
    if not certs and b"PRIVATE KEY" in data:
        low = data.lower()
        fam = "rsa" if b"rsa private key" in low else "ecdsa" if b"ec private key" in low else "unknown"
        yield RawFinding(
            scanner="certificate",
            asset_type=AssetType.KEY,
            raw_name=fam,
            parameters=AlgorithmParameters(extra={"fingerprint": "sha256:" + hashlib.sha256(data).hexdigest()[:24], "private": "true"}),
            evidence=Evidence(kind="key", locator=rel, snippet=f"private key ({fam}) — material not read"),
            confidence=Confidence.CONFIRMED,
        )
