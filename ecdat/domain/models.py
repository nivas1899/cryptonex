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
    data_classification: str = "INTERNAL"

    quantum_status: QuantumStatus = QuantumStatus.UNKNOWN
    quantum_status_reason: str = ""

    criticality: Criticality = Criticality.MEDIUM
    criticality_reason: str = ""

    mosca_inputs: MoscaInputs | None = None
    mosca_result: MoscaResult | None = None
    risk_score: float = 0.0
    hndl_exposed: bool = False

    recommendation: Recommendation | None = None


class GraphEdge(BaseModel):
    src: str
    dst: str
    kind: Literal["invokes", "implements", "depends-on", "signed-by", "contains", "issued-by"]


class Posture(BaseModel):
    total_assets: int = 0
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
    schema_version: str = "1.0"
    tool_version: str
    kb_version: str
    config_hash: str
    target: str
    started_at: datetime
    finished_at: datetime
    assets: list[CryptoAsset] = Field(default_factory=list)
    graph: list[GraphEdge] = Field(default_factory=list)
    posture: Posture = Field(default_factory=Posture)
    coverage: CoverageStatement = Field(default_factory=CoverageStatement)
