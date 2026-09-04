from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator

from ecdat.domain.enums import Severity
from ecdat.domain.models import SecurityFinding
from ecdat.knowledge import get_kb
from ecdat.scanners.base import Scanner, ScanContext, read_text, walk_files

_TEXT_EXT = {
    ".py", ".java", ".kt", ".scala", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx",
    ".go", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".cs", ".rb", ".php", ".rs",
    ".swift", ".sh", ".bash", ".conf", ".cnf", ".ini", ".cfg", ".properties",
    ".yaml", ".yml", ".toml", ".env",
}
_QUANTUM_CATEGORIES = {"weak-parameters", "hand-rolled-crypto"}


class MisuseScanner(Scanner):
    name = "misuse"

    def scan(self, ctx: ScanContext) -> Iterator[SecurityFinding]:  # type: ignore[override]
        kb = get_kb()
        rules = kb.misuse_rules
        for path in walk_files(ctx):
            if path.suffix.lower() not in _TEXT_EXT:
                continue
            text = read_text(path)
            if text is None:
                continue
            rel = ctx.rel(path)
            lines = text.splitlines()
            ext = path.suffix.lower()
            for rule in rules:
                if not rule.applies_to(ext):
                    continue
                for m in rule.rx.finditer(text):
                    lineno = text.count("\n", 0, m.start()) + 1
                    snippet = lines[lineno - 1].strip()[:200] if 0 < lineno <= len(lines) else m.group(0)
                    loc = f"{rel}:{lineno}"
                    fid = "SF-" + hashlib.blake2b(
                        f"{rule.id}|{loc}".encode(), digest_size=5
                    ).hexdigest()
                    yield SecurityFinding(
                        id=fid,
                        rule_id=rule.id,
                        title=rule.title,
                        severity=Severity(rule.severity),
                        category=rule.category,
                        cwe=rule.cwe,
                        location=loc,
                        snippet=snippet,
                        description=rule.description,
                        remediation=rule.remediation,
                        quantum_relevant=rule.category in _QUANTUM_CATEGORIES,
                    )


_STRIP = re.compile(r"(?:0x|\\x|[\s,\"'_;:{}()\[\]<>|&+])")


def _normalise_hex(text: str) -> str:
    return _STRIP.sub("", text).lower()


def scan_constants(ctx: ScanContext) -> Iterator[tuple[str, SecurityFinding, dict]]:
    """Detect hand-rolled / statically-linked crypto by known constant tables.

    Yields (kind, finding, asset_hint) where asset_hint feeds a CryptoAsset.
    """
    kb = get_kb()
    consts = kb.constants
    for path in walk_files(ctx):
        ext = path.suffix.lower()
        if ext in {".pem", ".crt", ".der", ".key"}:
            continue
        text = read_text(path)
        if text is None or len(text) > 1_500_000:
            continue
        norm = _normalise_hex(text)
        if len(norm) < 32:
            continue
        rel = ctx.rel(path)
        for c in consts:
            if c.hex and c.hex in norm:
                fid = "SF-" + hashlib.blake2b(f"{c.id}|{rel}".encode(), digest_size=5).hexdigest()
                is_crc = c.family == "UNKNOWN"
                finding = SecurityFinding(
                    id=fid,
                    rule_id=c.id,
                    title=(f"Non-crypto table ({c.name}) — verify it is not mistaken for a cipher"
                           if is_crc else f"Hand-rolled / embedded cryptography: {c.name}"),
                    severity=Severity.INFO if is_crc else Severity.HIGH,
                    category="hand-rolled-crypto",
                    cwe=None if is_crc else "CWE-1240",
                    location=rel,
                    snippet=c.name,
                    description=(c.note or f"The byte pattern of {c.name} was found in this file, "
                                f"indicating a cryptographic primitive implemented in-tree or "
                                f"statically linked rather than called through a maintained library."),
                    remediation=("Confirm this is a CRC and not a cipher." if is_crc else
                                 "Replace the in-tree implementation with a vetted library so it "
                                 "inherits constant-time code, security fixes, and PQC options."),
                    quantum_relevant=not is_crc,
                )
                asset_hint = {} if is_crc else {
                    "raw_name": c.family, "family": c.family, "primitive": c.primitive,
                    "locator": rel, "rule_id": c.id, "name": c.name,
                }
                yield ("constant", finding, asset_hint)
