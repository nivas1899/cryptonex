from __future__ import annotations

from cryptonex.scanners.base import Scanner
from cryptonex.scanners.certificate import CertificateScanner
from cryptonex.scanners.container import ContainerScanner
from cryptonex.scanners.dependency import DependencyScanner
from cryptonex.scanners.misuse import MisuseScanner
from cryptonex.scanners.source import SourceScanner

_REGISTRY: dict[str, type[Scanner]] = {
    "source": SourceScanner,
    "dependency": DependencyScanner,
    "certificate": CertificateScanner,
    "misuse": MisuseScanner,
    "container": ContainerScanner,
}

try:  # optional — needs `lief`
    from cryptonex.scanners.binary import BinaryScanner

    _REGISTRY["binary"] = BinaryScanner
except Exception:  # pragma: no cover
    BinaryScanner = None  # type: ignore

DEFAULT_SCANNERS = ["source", "dependency", "certificate", "misuse", "container"]
if "binary" in _REGISTRY:
    DEFAULT_SCANNERS.append("binary")


def all_scanners(names: list[str] | None = None) -> list[Scanner]:
    selected = names or DEFAULT_SCANNERS
    return [_REGISTRY[n]() for n in selected if n in _REGISTRY]


def available_scanners() -> list[str]:
    return list(_REGISTRY)
