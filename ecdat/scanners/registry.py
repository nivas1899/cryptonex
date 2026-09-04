from __future__ import annotations

from ecdat.scanners.base import Scanner
from ecdat.scanners.certificate import CertificateScanner
from ecdat.scanners.dependency import DependencyScanner
from ecdat.scanners.source import SourceScanner

_REGISTRY: dict[str, type[Scanner]] = {
    "source": SourceScanner,
    "dependency": DependencyScanner,
    "certificate": CertificateScanner,
}

DEFAULT_SCANNERS = ["source", "dependency", "certificate"]


def all_scanners(names: list[str] | None = None) -> list[Scanner]:
    selected = names or DEFAULT_SCANNERS
    return [_REGISTRY[n]() for n in selected if n in _REGISTRY]
