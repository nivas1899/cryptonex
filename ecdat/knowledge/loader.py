from __future__ import annotations

import functools
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

KB_DIR = Path(__file__).parent
RULES_DIR = KB_DIR / "rules"


def _load(name: str) -> dict[str, Any]:
    with (KB_DIR / name).open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _norm(s: str) -> str:
    return re.sub(r"\s+", "", str(s)).strip().lower()


def _ver_tuple(v: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", str(v))
    return tuple(int(p) for p in parts[:4]) or (0,)


@dataclass
class CompiledRule:
    id: str
    language: str
    rx: re.Pattern
    raw_name: str
    primitive: str | None = None
    family: str | None = None
    confidence: str = "medium"
    external: bool = False
    params_from: dict[str, str] = field(default_factory=dict)


@dataclass
class MisuseRule:
    id: str
    rx: re.Pattern
    title: str
    severity: str
    category: str
    cwe: str | None
    description: str
    remediation: str
    extensions: tuple[str, ...] = ()  # empty = all text files

    def applies_to(self, ext: str) -> bool:
        return not self.extensions or ext.lower() in self.extensions


@dataclass
class CryptoConstant:
    id: str
    hex: str
    family: str
    name: str
    primitive: str | None = None
    note: str | None = None


@dataclass
class KB:
    version: str
    algorithms: dict[str, Any]
    aliases: dict[str, Any]
    libraries: dict[str, Any]
    pqc: dict[str, Any]
    policy: dict[str, Any]
    rules_by_ext: dict[str, list[CompiledRule]]
    misuse_rules: list[MisuseRule]
    constants: list[CryptoConstant]

    # ---------- algorithm resolution ----------
    def resolve(
        self,
        raw_name: str,
        primitive_hint: str | None = None,
        family_hint: str | None = None,
    ) -> dict[str, Any]:
        key = _norm(raw_name)
        alias = self.aliases.get("aliases", {}).get(key)
        if alias:
            out = dict(alias)
            out.setdefault("name", raw_name)
            out.setdefault("params", {})
            # an explicit hint from a scanner (cert used for signing, jwt alg, ...)
            # wins over the alias default for ambiguous families
            if primitive_hint:
                out["primitive"] = primitive_hint
            return out
        # token fallback
        toks = re.split(r"[^a-z0-9]+", key)
        for t in toks:
            hit = self.aliases.get("tokens", {}).get(t)
            if hit:
                return {
                    "family": hit["family"],
                    "name": raw_name,
                    "primitive": primitive_hint or hit.get("primitive", "other"),
                    "params": {},
                }
        if family_hint:
            return {"family": family_hint, "name": raw_name,
                    "primitive": primitive_hint or "other", "params": {}}
        return {"family": "UNKNOWN", "name": raw_name,
                "primitive": primitive_hint or "other", "params": {}}

    # ---------- quantum status ----------
    def classify(self, family: str, primitive: str, params: dict[str, Any]) -> tuple[str, str]:
        fams = self.algorithms["families"]
        base = fams.get(family, fams["UNKNOWN"])
        status, reason = base["quantum_status"], base.get("reason", "")
        for ov in self.algorithms.get("overrides", []):
            w = ov["when"]
            if w.get("family") and w["family"] != family:
                continue
            ks = params.get("key_size")
            if "key_size" in w and ks != w["key_size"]:
                continue
            if "key_size_lte" in w and not (isinstance(ks, int) and ks <= w["key_size_lte"]):
                continue
            if "mode" in w and params.get("mode") != w["mode"]:
                continue
            if "hash" in w and (params.get("hash") or "").upper() != w["hash"].upper():
                continue
            if "parameter_set" in w and params.get("parameter_set") != w["parameter_set"]:
                continue
            return ov["quantum_status"], ov.get("reason", reason)
        return status, reason

    # ---------- libraries ----------
    def library_lookup(self, ecosystem: str, name: str, version: str | None) -> dict | None:
        name_l = name.lower()
        for lib in self.libraries.get("libraries", []):
            if lib["ecosystem"] != ecosystem:
                continue
            if lib["name"].lower() != name_l:
                continue
            entry = dict(lib)
            entry["flagged"] = bool(lib.get("flag"))
            if version and "version_lt" in lib:
                if _ver_tuple(version) < _ver_tuple(lib["version_lt"]):
                    entry["flagged"] = True
            return entry
        return None

    # ---------- recommendation ----------
    def pqc_rules(self) -> list[dict]:
        return self.pqc.get("rules", [])

    # ---------- policy helpers ----------
    def data_lifetime(self, data_class: str) -> float:
        return float(self.policy["data_lifetime_years"].get(
            data_class, self.policy["data_lifetime_years"]["INTERNAL"]))

    def migration_years(self, effort: str) -> float:
        return float(self.policy["migration_years"].get(effort, 1.5))

    def data_class_for_path(self, path: str) -> str | None:
        p = path.lower()
        for hint in self.policy.get("data_class_hints", []):
            if hint["keyword"] in p:
                return hint["class"]
        return None

    def is_external(self, path: str) -> bool:
        p = path.lower()
        return any(h in p for h in self.policy.get("external_hints", []))

    def context_tags(self, path: str) -> list[str]:
        p = path.lower()
        return [h["tag"] for h in self.policy.get("context_hints", []) if h["keyword"] in p]

    def criticality(
        self, paths: list[str], external: bool, data_class: str, is_ca_key: bool
    ) -> tuple[str, str]:
        cfg = self.policy["criticality"]
        blob = " ".join(paths).lower()
        score = 0.0
        hits: list[str] = []
        for kw, w in cfg["keyword_weights"].items():
            if kw in blob:
                score += w
                hits.append(f"{kw}({w:+g})")
        if external:
            score += cfg["external_weight"]
            hits.append(f"external(+{cfg['external_weight']})")
        if is_ca_key:
            score += cfg["ca_key_weight"]
            hits.append(f"ca-key(+{cfg['ca_key_weight']})")
        score += cfg["data_class_weights"].get(data_class, 10)
        hits.append(f"data:{data_class}")
        score = max(0.0, min(100.0, score))
        b = cfg["buckets"]
        bucket = (
            "critical" if score >= b["critical"] else
            "high" if score >= b["high"] else
            "medium" if score >= b["medium"] else
            "low"
        )
        return bucket, ", ".join(hits)

    def source_rules(self, ext: str) -> list[CompiledRule]:
        return self.rules_by_ext.get(ext.lower(), [])

    def resolve_family(self, raw: str) -> str:
        """Best-effort family for a constant / bare token."""
        return self.resolve(raw).get("family", "UNKNOWN")


@functools.lru_cache(maxsize=1)
def get_kb() -> KB:
    algorithms = _load("algorithms.yaml")
    aliases = _load("aliases.yaml")
    libraries = _load("libraries.yaml")
    pqc = _load("pqc_mapping.yaml")
    policy = _load("policy.yaml")

    rules_by_ext: dict[str, list[CompiledRule]] = {}
    for rf in sorted(RULES_DIR.glob("*.yaml")):
        spec = yaml.safe_load(rf.read_text(encoding="utf-8"))
        lang = spec["language"]
        exts = spec["extensions"]
        compiled: list[CompiledRule] = []
        for r in spec["rules"]:
            try:
                rx = re.compile(r["regex"], re.IGNORECASE)
            except re.error as e:  # pragma: no cover
                raise ValueError(f"bad regex in rule {r['id']}: {e}") from e
            compiled.append(CompiledRule(
                id=r["id"], language=lang, rx=rx, raw_name=r["raw_name"],
                primitive=r.get("primitive"), family=r.get("family"),
                confidence=r.get("confidence", "medium"), external=bool(r.get("external")),
                params_from=r.get("params_from", {}),
            ))
        for e in exts:
            rules_by_ext.setdefault(e.lower(), []).extend(compiled)

    misuse_spec = _load("misuse.yaml")
    misuse_rules: list[MisuseRule] = []
    for r in misuse_spec.get("rules", []):
        try:
            rx = re.compile(r["regex"], re.IGNORECASE)
        except re.error as e:  # pragma: no cover
            raise ValueError(f"bad misuse regex {r['id']}: {e}") from e
        misuse_rules.append(MisuseRule(
            id=r["id"], rx=rx, title=r["title"], severity=r["severity"],
            category=r["category"], cwe=r.get("cwe"),
            description=r.get("description", ""), remediation=r.get("remediation", ""),
            extensions=tuple(e.lower() for e in r.get("extensions", [])),
        ))

    const_spec = _load("constants.yaml")
    constants = [
        CryptoConstant(
            id=c["id"], hex=c["hex"].lower(), family=c["family"], name=c["name"],
            primitive=c.get("primitive"), note=c.get("note"),
        )
        for c in const_spec.get("constants", [])
    ]

    return KB(
        version=str(algorithms.get("version", "dev")),
        algorithms=algorithms, aliases=aliases, libraries=libraries,
        pqc=pqc, policy=policy, rules_by_ext=rules_by_ext,
        misuse_rules=misuse_rules, constants=constants,
    )
