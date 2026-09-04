from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from ecdat.domain.enums import AssetType, Confidence
from ecdat.domain.models import AlgorithmParameters, Evidence, RawFinding
from ecdat.knowledge import get_kb
from ecdat.scanners.base import Scanner, ScanContext, read_text, walk_files

_MANIFESTS = {
    "requirements.txt": "pip", "requirements-dev.txt": "pip", "pipfile": "pip",
    "pyproject.toml": "pip", "package.json": "npm", "package-lock.json": "npm",
    "pom.xml": "maven", "build.gradle": "maven", "go.mod": "go",
}


class DependencyScanner(Scanner):
    name = "dependency"

    def scan(self, ctx: ScanContext) -> Iterator[RawFinding]:
        kb = get_kb()
        for path in walk_files(ctx):
            eco = _MANIFESTS.get(path.name.lower())
            if not eco:
                continue
            text = read_text(path)
            if text is None:
                continue
            ctx.mark(path)
            rel = ctx.rel(path)
            for name, version, lineno in _parse(eco, path, text):
                entry = kb.library_lookup(eco, name, version)
                if entry is None:
                    continue
                loc = f"{rel}:{lineno}" if lineno else rel
                vlabel = f"{name} {version}" if version else name
                yield RawFinding(
                    scanner=f"dependency.{eco}",
                    asset_type=AssetType.LIBRARY,
                    raw_name=vlabel,
                    family_hint=name,
                    parameters=AlgorithmParameters(extra={"ecosystem": eco, "version": version or "?"}),
                    evidence=Evidence(kind="dependency", locator=loc, snippet=vlabel),
                    confidence=Confidence.CONFIRMED,
                )
                if entry.get("flagged"):
                    for prov in entry.get("provides", []):
                        yield RawFinding(
                            scanner=f"dependency.{eco}",
                            asset_type=AssetType.ALGORITHM,
                            raw_name=prov["raw"],
                            primitive_hint=None,
                            evidence=Evidence(
                                kind="dependency",
                                locator=loc,
                                snippet=f"provided by {vlabel}",
                                rule_id=f"lib.{eco}.{name}",
                            ),
                            confidence=Confidence.MEDIUM,
                        )


def _parse(eco: str, path: Path, text: str) -> Iterator[tuple[str, str | None, int | None]]:
    lines = text.splitlines()
    if eco == "pip":
        for i, ln in enumerate(lines, 1):
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            m = re.match(r"([A-Za-z0-9_.\-]+)\s*(?:[=<>!~]=?\s*([0-9][\w.\-]*))?", s)
            if m:
                yield m.group(1).lower(), m.group(2), i
    elif eco == "npm":
        for i, ln in enumerate(lines, 1):
            m = re.match(r'\s*"([@A-Za-z0-9_./\-]+)"\s*:\s*"[\^~>=<]*([0-9][\w.\-]*)"', ln)
            if m:
                yield m.group(1), m.group(2), i
    elif eco == "maven":
        # crude <dependency> block parse
        blocks = re.findall(
            r"<dependency>(.*?)</dependency>", text, re.S | re.I
        )
        for b in blocks:
            gid = re.search(r"<groupId>\s*([^<]+?)\s*</groupId>", b, re.I)
            aid = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", b, re.I)
            ver = re.search(r"<version>\s*([^<]+?)\s*</version>", b, re.I)
            if gid and aid:
                coord = f"{gid.group(1)}:{aid.group(1)}"
                line = text.count("\n", 0, text.find(b)) + 1
                yield coord, (ver.group(1) if ver else None), line
    elif eco == "go":
        for i, ln in enumerate(lines, 1):
            m = re.match(r"\s*(?:require\s+)?([\w./\-]+)\s+v([0-9][\w.\-]*)", ln)
            if m and "/" in m.group(1):
                yield m.group(1), m.group(2), i
