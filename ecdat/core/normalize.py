from __future__ import annotations

import hashlib

from ecdat.domain.enums import AssetType, Primitive
from ecdat.domain.enums import CONFIDENCE_ORDER
from ecdat.domain.models import (
    AlgorithmParameters,
    CryptoAsset,
    Detection,
    GraphEdge,
    Location,
    RawFinding,
)
from ecdat.knowledge import get_kb


def _merge_params(base: dict, extra: AlgorithmParameters) -> AlgorithmParameters:
    out = AlgorithmParameters(**{k: v for k, v in base.items() if v is not None})
    for field in ("key_size", "curve", "mode", "padding", "hash", "parameter_set"):
        v = getattr(extra, field)
        if v is not None:
            setattr(out, field, v)
    out.extra.update(extra.extra)
    return out


def _identity(asset_type: str, family: str, name: str, p: AlgorithmParameters) -> str:
    if asset_type == AssetType.LIBRARY.value:
        sig = f"{name}|{p.extra.get('version', '')}"
    elif asset_type in (AssetType.CERTIFICATE.value, AssetType.KEY.value):
        sig = f"{family}|{p.extra.get('fingerprint', p.extra.get('subject', name))}"
    else:
        sig = "|".join([
            family, name,
            str(p.key_size or ""), p.curve or "", p.mode or "",
            p.padding or "", p.hash or "", p.parameter_set or "",
        ])
    h = hashlib.blake2b(f"{asset_type}|{sig}".encode(), digest_size=6).hexdigest()
    return f"CR-{h}"


def normalize(findings: list[RawFinding]) -> tuple[list[CryptoAsset], list[GraphEdge]]:
    kb = get_kb()
    assets: dict[str, CryptoAsset] = {}
    edges: set[tuple[str, str, str]] = set()

    for f in findings:
        if f.asset_type == AssetType.LIBRARY:
            family = f.family_hint or f.raw_name
            name = f.raw_name
            primitive = Primitive.OTHER
            params = f.parameters
        else:
            res = kb.resolve(
                f.raw_name,
                f.primitive_hint.value if f.primitive_hint else None,
                f.family_hint,
            )
            family = res["family"]
            name = res.get("name") or f.raw_name
            try:
                primitive = Primitive(res.get("primitive") or "other")
            except ValueError:
                primitive = Primitive.OTHER
            params = _merge_params(res.get("params", {}), f.parameters)

        aid = _identity(f.asset_type.value, family, name, params)
        component = f.evidence.locator.split(":")[0] if ":" in f.evidence.locator else f.evidence.locator
        line = None
        if ":" in f.evidence.locator:
            tail = f.evidence.locator.rsplit(":", 1)[-1]
            line = int(tail) if tail.isdigit() else None

        if aid not in assets:
            assets[aid] = CryptoAsset(
                id=aid,
                asset_type=f.asset_type,
                name=name,
                primitive=primitive,
                algorithm_family=family,
                parameters=params,
                detection=Detection(scanner=f.scanner, evidence=[f.evidence], confidence=f.confidence),
                locations=[Location(component=component, line=line)],
                occurrences=1,
                external_facing=f.external_facing,
                data_classification=f.data_classification or "INTERNAL",
            )
        else:
            a = assets[aid]
            a.occurrences += 1
            if not any(ev.locator == f.evidence.locator for ev in a.detection.evidence):
                a.detection.evidence.append(f.evidence)
            if not any(loc.component == component and loc.line == line for loc in a.locations):
                a.locations.append(Location(component=component, line=line))
            if CONFIDENCE_ORDER.index(f.confidence) > CONFIDENCE_ORDER.index(a.detection.confidence):
                a.detection.confidence = f.confidence
            a.external_facing = a.external_facing or f.external_facing
            # fill missing params
            for fld in ("key_size", "curve", "mode", "padding", "hash", "parameter_set"):
                if getattr(a.parameters, fld) is None and getattr(params, fld) is not None:
                    setattr(a.parameters, fld, getattr(params, fld))

        edges.add((component, aid, "depends-on" if f.asset_type == AssetType.LIBRARY else "invokes"))

    graph = [GraphEdge(src=s, dst=d, kind=k) for (s, d, k) in sorted(edges)]  # type: ignore[arg-type]
    ordered = sorted(assets.values(), key=lambda a: a.id)
    return ordered, graph
