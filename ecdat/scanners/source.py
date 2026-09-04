from __future__ import annotations

import re
from collections.abc import Iterator

from ecdat.domain.enums import AssetType, Confidence, Primitive
from ecdat.domain.models import AlgorithmParameters, Evidence, RawFinding
from ecdat.knowledge import get_kb
from ecdat.scanners.base import Scanner, ScanContext, read_text, walk_files

_CONF = {
    "confirmed": Confidence.CONFIRMED, "high": Confidence.HIGH,
    "medium": Confidence.MEDIUM, "low": Confidence.LOW,
}
_TEMPLATE = re.compile(r"\{(\w+)\}")


class SourceScanner(Scanner):
    name = "source"

    def scan(self, ctx: ScanContext) -> Iterator[RawFinding]:
        kb = get_kb()
        for path in walk_files(ctx):
            ext = path.suffix.lower()
            rules = kb.source_rules(ext)
            if not rules:
                continue
            text = read_text(path)
            if text is None:
                ctx.skip("unreadable")
                continue
            ctx.mark(path)
            lines = text.splitlines()
            rel = ctx.rel(path)
            for rule in rules:
                for m in rule.rx.finditer(text):
                    gd = {k: v for k, v in m.groupdict().items() if v is not None}
                    raw = _TEMPLATE.sub(lambda mm: gd.get(mm.group(1), mm.group(0)), rule.raw_name)
                    lineno = text.count("\n", 0, m.start()) + 1
                    params = AlgorithmParameters()
                    if "bits" in gd and gd["bits"].isdigit():
                        params.key_size = int(gd["bits"])
                    if "keysize" in gd and gd["keysize"].isdigit():
                        params.key_size = int(gd["keysize"])
                    if "curve" in gd:
                        params.curve = gd["curve"]
                    if "hash" in gd:
                        params.hash = _canon_hash(gd["hash"])
                    if "mode" in gd:
                        params.mode = gd["mode"].upper()
                    if "padding" in gd:
                        params.padding = gd["padding"]
                    # generic params_from mapping declared on the rule
                    for field_name, group in rule.params_from.items():
                        if group in gd and gd[group]:
                            v = gd[group]
                            if field_name == "key_size" and str(v).isdigit():
                                params.key_size = int(v)
                            elif field_name == "hash":
                                params.hash = _canon_hash(v)
                            elif hasattr(params, field_name):
                                setattr(params, field_name, str(v).upper() if field_name == "mode" else v)
                    snippet = (lines[lineno - 1].strip()[:200] if 0 < lineno <= len(lines) else raw)
                    prim = None
                    if rule.primitive:
                        try:
                            prim = Primitive(rule.primitive)
                        except ValueError:
                            prim = None
                    yield RawFinding(
                        scanner=f"source.{rule.language}",
                        asset_type=AssetType.ALGORITHM,
                        raw_name=raw,
                        primitive_hint=prim,
                        family_hint=rule.family,
                        parameters=params,
                        external_facing=rule.external or kb.is_external(rel),
                        evidence=Evidence(
                            kind="source-span",
                            locator=f"{rel}:{lineno}",
                            snippet=snippet,
                            rule_id=rule.id,
                        ),
                        confidence=_CONF.get(rule.confidence, Confidence.MEDIUM),
                    )


def _canon_hash(h: str) -> str:
    h = h.lower().replace("_", "-")
    table = {"sha1": "SHA-1", "sha-1": "SHA-1", "sha256": "SHA-256", "sha-256": "SHA-256",
             "sha384": "SHA-384", "sha512": "SHA-512", "md5": "MD5"}
    return table.get(h, h.upper())
