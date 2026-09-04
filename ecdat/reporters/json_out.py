from __future__ import annotations

from ecdat.domain.models import ScanResult


def to_json(result: ScanResult) -> str:
    return result.model_dump_json(indent=2)
