from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from ecdat.domain.enums import AssetType, Confidence
from ecdat.domain.models import AlgorithmParameters, Evidence, RawFinding, SecurityFinding
from ecdat.domain.enums import Severity
from ecdat.knowledge import get_kb
from ecdat.scanners.base import Scanner, ScanContext, read_text, walk_files

_MANIFESTS = {
    "requirements.txt": "pip", "requirements-dev.txt": "pip", "requirements-test.txt": "pip",
    "pipfile": "pip", "pipfile.lock": "pip", "poetry.lock": "pip", "pyproject.toml": "pip",
    "package.json": "npm", "package-lock.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
    "pom.xml": "maven", "build.gradle": "maven", "build.gradle.kts": "maven",
    "go.mod": "go", "go.sum": "go",
    "cargo.toml": "cargo", "cargo.lock": "cargo",
    "gemfile": "gem", "gemfile.lock": "gem",
    "composer.json": "composer", "composer.lock": "composer",
    "packages.config": "nuget", "podfile": "cocoapods", "podfile.lock": "cocoapods",
}
_CSPROJ = re.compile(r"\.csproj$|\.fsproj$", re.I)


class DependencyScanner(Scanner):
    name = "dependency"

    def scan(self, ctx: ScanContext) -> Iterator[RawFinding | SecurityFinding]:
        kb = get_kb()
        advisories = kb.advisories
        for path in walk_files(ctx):
            eco = _MANIFESTS.get(path.name.lower())
            if eco is None and _CSPROJ.search(path.name):
                eco = "nuget"
            if not eco:
                continue
            text = read_text(path)
            if text is None:
                continue
            ctx.mark(path)
            rel = ctx.rel(path)
            for name, version, lineno in _parse(eco, path, text):
                loc = f"{rel}:{lineno}" if lineno else rel
                vlabel = f"{name} {version}" if version else name

                # known-vulnerable version advisory
                for adv in advisories:
                    if adv["ecosystem"] == eco and adv["name"].lower() == name.lower():
                        if _in_range(version, adv.get("affected", "")):
                            yield SecurityFinding(
                                id="SF-adv-" + adv["id"].replace(" ", ""),
                                rule_id=adv["id"],
                                title=f"{name} {version or ''}: {adv['title']}",
                                severity=Severity(adv.get("severity", "high")),
                                category="vulnerable-dependency",
                                cwe=adv.get("cwe"),
                                location=loc,
                                snippet=vlabel,
                                description=adv.get("description", ""),
                                remediation=adv.get("fix", f"Upgrade {name} to a fixed version."),
                                quantum_relevant=False,
                            )

                entry = kb.library_lookup(eco, name, version)
                if entry is None:
                    continue
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
                            evidence=Evidence(kind="dependency", locator=loc,
                                              snippet=f"provided by {vlabel}",
                                              rule_id=f"lib.{eco}.{name}"),
                            confidence=Confidence.MEDIUM,
                        )


def _in_range(version: str | None, spec: str) -> bool:
    """Very small range check: '<1.7.1' or '>=1.0,<2.0' or exact."""
    if not version:
        return False
    v = _vt(version)
    if not spec:
        return True
    ok = True
    for clause in spec.split(","):
        clause = clause.strip()
        m = re.match(r"(<=|>=|<|>|==)?\s*([0-9][\w.\-]*)", clause)
        if not m:
            continue
        op, rv = m.group(1) or "==", _vt(m.group(2))
        ok = ok and {
            "<": v < rv, "<=": v <= rv, ">": v > rv, ">=": v >= rv, "==": v == rv,
        }[op]
    return ok


def _vt(s: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", str(s))[:4]) or (0,)


def _parse(eco: str, path: Path, text: str) -> Iterator[tuple[str, str | None, int | None]]:
    lines = text.splitlines()
    if eco == "pip":
        for i, ln in enumerate(lines, 1):
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            m = re.match(r"([A-Za-z0-9_.\-]+)\s*(?:[=<>!~]=?\s*[\"']?([0-9][\w.\-]*))?", s)
            if m:
                yield m.group(1).lower(), m.group(2), i
    elif eco == "npm":
        for i, ln in enumerate(lines, 1):
            m = re.match(r'\s*"([@A-Za-z0-9_./\-]+)"\s*:\s*"[\^~>=<]*([0-9][\w.\-]*)"', ln)
            if m and m.group(1) not in ("version", "resolved"):
                yield m.group(1), m.group(2), i
    elif eco == "maven":
        for b in re.findall(r"<dependency>(.*?)</dependency>", text, re.S | re.I):
            gid = re.search(r"<groupId>\s*([^<]+?)\s*</groupId>", b, re.I)
            aid = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", b, re.I)
            ver = re.search(r"<version>\s*([^<]+?)\s*</version>", b, re.I)
            if gid and aid:
                line = text.count("\n", 0, text.find(b)) + 1
                yield f"{gid.group(1)}:{aid.group(1)}", (ver.group(1) if ver else None), line
        for i, ln in enumerate(lines, 1):  # gradle
            m = re.search(r"['\"]([\w.\-]+):([\w.\-]+):([0-9][\w.\-]*)['\"]", ln)
            if m:
                yield f"{m.group(1)}:{m.group(2)}", m.group(3), i
    elif eco == "go":
        for i, ln in enumerate(lines, 1):
            m = re.match(r"\s*(?:require\s+)?([\w./\-]+)\s+v([0-9][\w.\-]*)", ln)
            if m and "/" in m.group(1):
                yield m.group(1), m.group(2), i
    elif eco == "cargo":
        cur = None
        for i, ln in enumerate(lines, 1):
            s = ln.strip()
            if s.startswith("[[package]]"):
                cur = {}
            m = re.match(r'(\w+)\s*=\s*"([^"]+)"', s)
            if m and cur is not None:
                cur[m.group(1)] = m.group(2)
                if "name" in cur and "version" in cur:
                    yield cur["name"], cur["version"], i
                    cur = {}
            m2 = re.match(r'([A-Za-z0-9_\-]+)\s*=\s*(?:\{[^}]*version\s*=\s*)?"([~^]?[0-9][\w.\-]*)"', s)
            if m2 and cur is None:
                yield m2.group(1), m2.group(2).lstrip("~^"), i
    elif eco == "gem":
        for i, ln in enumerate(lines, 1):
            m = re.match(r"\s*gem\s+['\"]([\w\-]+)['\"](?:\s*,\s*['\"][~>=<\s]*([0-9][\w.\-]*)['\"])?", ln)
            if m:
                yield m.group(1), m.group(2), i
            m2 = re.match(r"\s{4}([\w\-]+)\s+\(([0-9][\w.\-]*)\)", ln)  # Gemfile.lock
            if m2:
                yield m2.group(1), m2.group(2), i
    elif eco == "composer":
        for i, ln in enumerate(lines, 1):
            m = re.search(r'"([\w\-]+/[\w\-]+)"\s*:\s*"[\^~>=<v\s]*([0-9][\w.\-]*)"', ln)
            if m:
                yield m.group(1), m.group(2), i
    elif eco == "nuget":
        for i, ln in enumerate(lines, 1):
            m = re.search(r'(?:id|Include)="([\w.\-]+)"\s+[Vv]ersion="([0-9][\w.\-]*)"', ln)
            if m:
                yield m.group(1), m.group(2), i
    elif eco == "cocoapods":
        for i, ln in enumerate(lines, 1):
            m = re.match(r"\s*(?:pod\s+)?['\"]([\w+\-]+)['\"](?:\s*,\s*['\"][~>=<\s]*([0-9][\w.\-]*)['\"])?", ln)
            if m:
                yield m.group(1), m.group(2), i
