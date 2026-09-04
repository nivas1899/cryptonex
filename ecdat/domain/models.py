from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from ecdat.domain.enums import (
    AssetType,
    Confidence,
    Criticality,
    Effort,
    Primitive,
    QuantumStatus,
    Severity,
)

EvidenceKind = Literal[
    "source-span",
    "dependency",
    "certificate",
    "key",
    "binary-symbol",
    "binary-string",
    "constant",
    "config",
    "container-layer",
]


class Evidence(BaseModel):
    kind: EvidenceKind
    locator: str
    snippet: str | None = None
    rule_id: str | None = None
    layer: str | None = None


class Detection(BaseModel):
    scanner: str
    evidence: list[Evidence] = Field(default_factory=list)
    confidence: Confidence = Confidence.MEDIUM


class AlgorithmParameters(BaseModel):
    key_size: int | None = None
    curve: str | None = None
    mode: str | None = None
    padding: str | None = None
    hash: str | None = None
    parameter_set: str | None = None
    extra: dict[str, str] = Field(default_factory=dict)

    def is_empty(self) -> bool:
        return not any(
            (self.key_size, self.curve, self.mode, self.padding, self.hash, self.parameter_set)
        ) and not self.extra


class Location(BaseModel):
    component: str
    line: int | None = None
    contributor: str | None = None


class AssessmentBasis(BaseModel):
    """How each part of an asset's assessment was derived — so a reviewer can
    tell observed fact from heuristic inference from operator assumption."""
    observed: list[str] = Field(default_factory=list)     # evidence-backed
    kb_derived: list[str] = Field(default_factory=list)   # deterministic KB lookup (cited)
    inferred: list[str] = Field(default_factory=list)     # heuristic (path keywords, …)
    assumed: list[str] = Field(default_factory=list)      # operator-set (X / Y / Z)


class MoscaInputs(BaseModel):
    data_lifetime_years: float  # X
    migration_years: float  # Y
    crqc_year: int  # Z
    now_year: int


class MoscaResult(BaseModel):
    at_risk: bool
    exposure_years: float
    formula: str


class Recommendation(BaseModel):
    rule_id: str
    target_algorithm: str
    hybrid_option: str | None = None
    nist_category: int | None = None
    library_support: list[str] = Field(default_factory=list)
    protocol_support: str | None = None
    latency_class: str | None = None
    migration_effort: Effort = Effort.MEDIUM
    rationale: str = ""


class RawFinding(BaseModel):
    scanner: str
    asset_type: AssetType
    raw_name: str
    primitive_hint: Primitive | None = None
    family_hint: str | None = None
    parameters: AlgorithmParameters = Field(default_factory=AlgorithmParameters)
    evidence: Evidence
    confidence: Confidence = Confidence.MEDIUM
    external_facing: bool = False
    data_classification: str | None = None


class CryptoAsset(BaseModel):
    id: str
    asset_type: AssetType
    name: str
    primitive: Primitive = Primitive.OTHER
    algorithm_family: str = "UNKNOWN"
    parameters: AlgorithmParameters = Field(default_factory=AlgorithmParameters)
    detection: Detection
    locations: list[Location] = Field(default_factory=list)
    occurrences: int = 1

    external_facing: bool = False
    external_facing_reason: str = ""
    data_classification: str = "INTERNAL"
    data_classification_reason: str = ""

    quantum_status: QuantumStatus = QuantumStatus.UNKNOWN
    quantum_status_reason: str = ""

    criticality: Criticality = Criticality.MEDIUM
    criticality_reason: str = ""

    assessment: AssessmentBasis = Field(default_factory=AssessmentBasis)

    mosca_inputs: MoscaInputs | None = None
    mosca_result: MoscaResult | None = None
    risk_score: float = 0.0
    hndl_exposed: bool = False

    recommendation: Recommendation | None = None
    test_only: bool = False  # every location is a test / example / fixture path


class GraphEdge(BaseModel):
    src: str
    dst: str
    kind: Literal["invokes", "implements", "depends-on", "signed-by", "contains", "issued-by"]


class SecurityFinding(BaseModel):
    """A cryptographic weakness or misuse — distinct from an inventoried asset."""
    id: str
    rule_id: str
    title: str
    severity: Severity
    category: str  # crypto-misuse | weak-rng | cert-validation | hardcoded-secret |
                   # algorithm-confusion | hand-rolled-crypto | weak-parameters | quantum
    cwe: str | None = None
    location: str
    snippet: str | None = None
    description: str = ""
    remediation: str = ""
    quantum_relevant: bool = False
    test_path: bool = False


class MigrationWave(BaseModel):
    order: int
    name: str
    effort: str
    asset_count: int
    risk_reduction: float          # sum of risk_score across the wave's assets
    example_assets: list[str] = Field(default_factory=list)


class PQCReadiness(BaseModel):
    crypto_agility_index: float = 100.0   # 0..100, higher = easier to migrate
    agility_grade: str = "A"
    migration_waves: list[MigrationWave] = Field(default_factory=list)
    nqm_phase_counts: dict[str, int] = Field(default_factory=dict)   # inventory-2027 / high-priority-2028 / full-2029
    quantum_risk_timeline: list[dict] = Field(default_factory=list)  # [{year, exposed_assets}]
    hndl_at_rest_count: int = 0


class Posture(BaseModel):
    total_assets: int = 0
    test_only_assets: int = 0            # inventoried but excluded from the grade
    by_status: dict[str, int] = Field(default_factory=dict)
    by_criticality: dict[str, int] = Field(default_factory=dict)
    hndl_count: int = 0
    at_risk_count: int = 0
    posture_score: float = 100.0
    grade: str = "A"


class CoverageStatement(BaseModel):
    scanners_run: list[str] = Field(default_factory=list)
    files_parsed: int = 0
    files_skipped: dict[str, int] = Field(default_factory=dict)
    known_limitations: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    schema_version: str = "1.1"
    tool_version: str
    kb_version: str
    config_hash: str
    target: str
    started_at: datetime
    finished_at: datetime
    assets: list[CryptoAsset] = Field(default_factory=list)
    findings: list[SecurityFinding] = Field(default_factory=list)
    graph: list[GraphEdge] = Field(default_factory=list)
    posture: Posture = Field(default_factory=Posture)
    pqc_readiness: PQCReadiness = Field(default_factory=PQCReadiness)
    coverage: CoverageStatement = Field(default_factory=CoverageStatement)
