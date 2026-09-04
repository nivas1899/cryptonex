from __future__ import annotations

import re
from collections.abc import Iterator

import lief

from cryptonex.domain.enums import AssetType, Confidence, Primitive
from cryptonex.domain.models import AlgorithmParameters, Evidence, RawFinding
from cryptonex.scanners.base import Scanner, ScanContext, walk_files

_BIN_EXT = {".so", ".dll", ".dylib", ".exe", ".bin", ".elf", ".o", ".a", ""}
_MAGIC = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe")

# linked crypto library -> a representative primitive to record
_LIB_HINTS = {
    "libcrypto": "rsa", "libssl": "x25519", "libmbedtls": "rsa", "libmbedcrypto": "rsa",
    "libwolfssl": "rsa", "libgnutls": "rsa", "libnss3": "rsa", "libsodium": "x25519",
    "libgcrypt": "rsa", "bcrypt.dll": "rsa", "ncrypt.dll": "rsa", "libcrypt": "rsa",
    "liboqs": "ml-kem",
}
_SYMBOL_HINTS = [
    (re.compile(r"^RSA_(generate_key|sign|public_encrypt)"), "rsa", Primitive.PKE),
    (re.compile(r"^EC(DSA)?_(KEY_new|sign|do_sign|generate_key)"), "ecdsa", Primitive.SIGNATURE),
    (re.compile(r"^DH_(generate_key|compute_key)"), "dh", Primitive.KEY_AGREEMENT),
    (re.compile(r"^(MD5|MD5_Init)$"), "md5", Primitive.HASH),
    (re.compile(r"^SHA1(_Init)?$"), "sha1", Primitive.HASH),
    (re.compile(r"^SHA256(_Init)?$"), "sha256", Primitive.HASH),
    (re.compile(r"DES_ede3|DES_ncbc"), "3des", Primitive.BLOCK_CIPHER),
    (re.compile(r"^RC4"), "rc4", Primitive.STREAM_CIPHER),
    (re.compile(r"chacha20|ChaCha20"), "chacha20", Primitive.STREAM_CIPHER),
    (re.compile(r"(ml_kem|OQS_KEM|mlkem)", re.I), "ml-kem", Primitive.KEM),
    (re.compile(r"(ml_dsa|OQS_SIG|mldsa)", re.I), "ml-dsa", Primitive.SIGNATURE),
]
_BANNER = re.compile(rb"(OpenSSL\s+\d+\.\d+\.\d+[a-z]?|mbed ?TLS \d+\.\d+\.\d+|BoringSSL|wolfSSL \d+\.\d+\.\d+|GnuTLS \d+\.\d+\.\d+)")
_OID = re.compile(rb"\x06[\x03-\x09](\x2a\x86\x48\x86\xf7\x0d\x01\x01[\x04-\x0e])")  # sha*WithRSA family


class BinaryScanner(Scanner):
    name = "binary"

    def scan(self, ctx: ScanContext) -> Iterator[RawFinding]:
        for path in walk_files(ctx):
            try:
                head = path.read_bytes()[:4]
            except OSError:
                continue
            if not (path.suffix.lower() in _BIN_EXT and head.startswith(_MAGIC)):
                continue
            rel = ctx.rel(path)
            try:
                bin_ = lief.parse(str(path))
            except Exception:
                ctx.skip("binary-parse-failed")
                continue
            if bin_ is None:
                continue
            ctx.mark(path)
            yield from self._analyse(bin_, path, rel, ctx)

    def _analyse(self, bin_, path, rel, ctx) -> Iterator[RawFinding]:
        seen: set[str] = set()

        def emit(raw, prim, conf, ev_kind, snippet, rule):
            key = f"{raw}|{prim}"
            if key in seen:
                return None
            seen.add(key)
            return RawFinding(
                scanner="binary",
                asset_type=AssetType.ALGORITHM,
                raw_name=raw,
                primitive_hint=prim,
                parameters=AlgorithmParameters(extra={"source": "binary"}),
                evidence=Evidence(kind=ev_kind, locator=rel, snippet=snippet[:200], rule_id=rule),
                confidence=conf,
            )

        # dynamic linkage
        try:
            libs = [str(x) for x in getattr(bin_, "libraries", [])]
        except Exception:
            libs = []
        for lib in libs:
            for key, raw in _LIB_HINTS.items():
                if key in lib.lower():
                    f = emit(raw, None, Confidence.MEDIUM, "binary-symbol",
                             f"links {lib}", f"bin.lib.{key}")
                    if f:
                        yield f

        # imported / exported symbols
        try:
            syms = [s.name for s in bin_.symbols][:6000]
        except Exception:
            syms = []
        for name in syms:
            if not name:
                continue
            for rx, raw, prim in _SYMBOL_HINTS:
                if rx.search(name):
                    f = emit(raw, prim, Confidence.HIGH, "binary-symbol",
                             f"symbol {name}", "bin.sym")
                    if f:
                        yield f

        # strings / version banners / embedded certs
        try:
            raw_bytes = path.read_bytes()
        except OSError:
            raw_bytes = b""
        for m in _BANNER.finditer(raw_bytes):
            f = emit("x25519" if b"OpenSSL 3" in m.group(0) else "rsa", None,
                     Confidence.MEDIUM, "binary-string",
                     m.group(0).decode("latin1"), "bin.banner")
            if f:
                yield f
        if b"-----BEGIN CERTIFICATE-----" in raw_bytes or b"-----BEGIN PRIVATE KEY-----" in raw_bytes:
            f = emit("rsa", Primitive.SIGNATURE, Confidence.MEDIUM, "binary-string",
                     "embedded PEM block", "bin.pem")
            if f:
                yield f
