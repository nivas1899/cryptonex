"""Container-image collector.

Accepts an image saved as a tar (`docker save img -o img.tar`), a `.tar.gz`,
or an OCI layout directory. Unpacks the layers into a merged root filesystem
(honouring whiteouts) and runs the source / dependency / certificate / binary
collectors over it. Fully offline — no registry access.
"""
from __future__ import annotations

import json
import tarfile
import tempfile
from collections.abc import Iterator
from pathlib import Path

from cryptonex.domain.enums import Severity
from cryptonex.domain.models import RawFinding, SecurityFinding
from cryptonex.scanners.base import Scanner, ScanContext, walk_files

MAX_TOTAL_BYTES = 4_000_000_000     # zip-bomb guard
MAX_ENTRIES = 400_000


def _is_image_tar(path: Path) -> bool:
    if path.suffix.lower() not in (".tar", ".tgz") and not path.name.endswith(".tar.gz"):
        return False
    try:
        with tarfile.open(path) as tf:
            names = tf.getnames()[:2000]
        return any(n in ("manifest.json", "index.json", "oci-layout") or n.endswith("/manifest.json")
                   for n in names)
    except Exception:
        return False


class ContainerScanner(Scanner):
    name = "container"

    def scan(self, ctx: ScanContext) -> Iterator[RawFinding | SecurityFinding]:
        targets: list[Path] = []
        root = ctx.root
        if root.is_file() and _is_image_tar(root):
            targets = [root]
        elif root.is_dir():
            if (root / "oci-layout").exists():
                targets = [root]
            else:
                targets = [p for p in walk_files(ctx) if _is_image_tar(p)]
        if not targets:
            return

        for tgt in targets:
            rel = ctx.rel(tgt)
            if rel in (".", ""):
                rel = tgt.name
            with tempfile.TemporaryDirectory(prefix="cryptonex-img-") as tmp:
                merged = Path(tmp) / "rootfs"
                merged.mkdir()
                layer_digests = _unpack(tgt, merged)
                if not layer_digests:
                    ctx.skip("container-unpack-failed")
                    continue
                ctx.mark(tgt)

                # run the file collectors over the merged rootfs
                sub = ScanContext(root=merged)
                from cryptonex.scanners.certificate import CertificateScanner
                from cryptonex.scanners.dependency import DependencyScanner
                from cryptonex.scanners.misuse import MisuseScanner
                from cryptonex.scanners.source import SourceScanner

                collectors = [SourceScanner(), DependencyScanner(),
                              CertificateScanner(), MisuseScanner()]
                try:
                    from cryptonex.scanners.binary import BinaryScanner
                    collectors.append(BinaryScanner())
                except Exception:
                    pass

                image_ref = f"{rel}"
                for c in collectors:
                    for item in c.scan(sub):
                        if isinstance(item, SecurityFinding):
                            item.location = f"{image_ref}!{item.location}"
                            yield item
                        else:
                            # re-anchor the evidence to the image
                            item.evidence.locator = f"{image_ref}!{item.evidence.locator}"
                            item.evidence.layer = layer_digests[-1][:19] if layer_digests else None
                            item.scanner = f"container.{item.scanner}"
                            yield item
                ctx._parsed |= sub._parsed

                # image config -> base image + crypto-ish env vars
                cfg = _read_config(tgt)
                if cfg:
                    for env in cfg.get("Config", {}).get("Env", []) or []:
                        low = env.lower()
                        if any(k in low for k in ("key", "secret", "token", "cert", "tls", "pass")):
                            yield SecurityFinding(
                                id="SF-imgenv-" + str(abs(hash(env)) % 10**8),
                                rule_id="container.env-secret",
                                title="Secret-looking value in image ENV",
                                severity=Severity.MEDIUM,
                                category="hardcoded-secret",
                                cwe="CWE-798",
                                location=f"{image_ref}!<image config>",
                                snippet=env.split("=")[0] + "=…",
                                description="Environment variables baked into an image layer are visible "
                                            "to anyone who can pull the image.",
                                remediation="Inject secrets at runtime (orchestrator secret, mounted file), "
                                            "not via ENV in the Dockerfile.",
                            )


def _safe_members(tf: tarfile.TarFile, dest: Path):
    seen = 0
    total = 0
    for m in tf:
        seen += 1
        total += max(m.size, 0)
        if seen > MAX_ENTRIES or total > MAX_TOTAL_BYTES:
            break
        name = m.name.lstrip("/").replace("..", "__")
        target = (dest / name).resolve()
        if not str(target).startswith(str(dest.resolve())):
            continue
        yield m


def _unpack(image: Path, merged: Path) -> list[str]:
    """Extract every layer of *image* into *merged* in order. Returns layer digests."""
    digests: list[str] = []
    with tempfile.TemporaryDirectory(prefix="cryptonex-layers-") as ld:
        layers_dir = Path(ld)
        try:
            with tarfile.open(image) as tf:
                tf.extractall(layers_dir, members=_safe_members(tf, layers_dir))
        except Exception:
            return []

        manifest_p = layers_dir / "manifest.json"
        layer_paths: list[Path] = []
        if manifest_p.exists():  # docker save format
            man = json.loads(manifest_p.read_text())
            for entry in man:
                for lp in entry.get("Layers", []):
                    layer_paths.append(layers_dir / lp)
        else:  # OCI layout
            idx = layers_dir / "index.json"
            blobs = layers_dir / "blobs"
            if idx.exists() and blobs.exists():
                for b in sorted(blobs.rglob("*")):
                    if b.is_file():
                        layer_paths.append(b)

        for lp in layer_paths:
            if not lp.exists():
                continue
            digests.append(lp.name)
            try:
                with tarfile.open(lp) as ltf:
                    for m in _safe_members(ltf, merged):
                        base = Path(m.name).name
                        if base == ".wh..wh..opq":
                            d = merged / Path(m.name).parent
                            if d.exists():
                                for c in d.iterdir():
                                    _rm(c)
                            continue
                        if base.startswith(".wh."):
                            victim = merged / Path(m.name).parent / base[4:]
                            _rm(victim)
                            continue
                        try:
                            ltf.extract(m, merged, set_attrs=False)
                        except Exception:
                            pass
            except Exception:
                continue
    return digests


def _rm(p: Path) -> None:
    try:
        if p.is_dir():
            for c in p.iterdir():
                _rm(c)
            p.rmdir()
        elif p.exists() or p.is_symlink():
            p.unlink()
    except OSError:
        pass


def _read_config(image: Path) -> dict | None:
    try:
        with tarfile.open(image) as tf:
            names = tf.getnames()
            man = next((n for n in names if n == "manifest.json"), None)
            if not man:
                return None
            entry = json.loads(tf.extractfile("manifest.json").read())[0]
            cfg_name = entry.get("Config")
            if cfg_name and cfg_name in names:
                return json.loads(tf.extractfile(cfg_name).read())
    except Exception:
        return None
    return None
