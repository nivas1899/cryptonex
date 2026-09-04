from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from ecdat.domain.models import RawFinding

from ecdat.domain.paths import is_test_path  # noqa: F401  (re-exported for scanners)

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "__pycache__",
    ".venv", "venv", ".mypy_cache", ".pytest_cache", "target", ".tox",
    # test-vector corpora — thousands of files, never application code
    "vectors", "cryptography_vectors", "test-vectors", "testvectors", "wycheproof",
}
MAX_FILE_BYTES = 2_000_000


@dataclass
class ScanContext:
    root: Path
    _parsed: set = field(default_factory=set)
    files_skipped: dict[str, int] = field(default_factory=dict)

    @property
    def files_parsed(self) -> int:
        return len(self._parsed)

    @files_parsed.setter
    def files_parsed(self, _v: int) -> None:  # tolerate `ctx.files_parsed += 1`
        pass

    def mark(self, p) -> None:
        self._parsed.add(str(p))

    def skip(self, reason: str) -> None:
        self.files_skipped[reason] = self.files_skipped.get(reason, 0) + 1

    def rel(self, p: Path) -> str:
        try:
            return str(p.relative_to(self.root))
        except ValueError:
            return str(p)


class Scanner(ABC):
    name: str = "scanner"

    @abstractmethod
    def scan(self, ctx: ScanContext) -> Iterator[RawFinding]: ...


def walk_files(ctx: ScanContext) -> Iterator[Path]:
    """Yield every non-skipped regular file under the scan root."""
    root = ctx.root
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if not p.is_file():
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                ctx.skip("too-large")
                continue
        except OSError:
            continue
        if p.name.endswith(".min.js"):
            ctx.skip("minified")
            continue
        yield p


def read_text(p: Path) -> str | None:
    try:
        data = p.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:1024]:
        return None
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:  # pragma: no cover
        return None
