"""Shared helper for loading collector manifest metadata."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def load_manifest_for_slug(
    source_slug: str,
    *,
    repo_root: Path | None = None,
) -> tuple[dict[str, Any] | None, str | None, str | None]:
    """Load collector manifest and return (manifest, hash, version)."""
    root = repo_root or Path(__file__).resolve().parent.parent
    manifest_path = root / "collectors" / source_slug / "manifest.json"
    if not manifest_path.exists():
        return None, None, None

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    canonical = json.dumps(
        manifest,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    manifest_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    manifest_version = str(manifest.get("version") or "").strip() or None
    return manifest, manifest_hash, manifest_version
