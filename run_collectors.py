#!/usr/bin/env python3
"""Run collectors by centralized profile configuration."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
COLLECTORS_DIR = ROOT / "collectors"


@dataclass(frozen=True)
class CollectorResult:
    slug: str
    returncode: int
    duration_seconds: float
    stdout: str
    stderr: str
    timed_out: bool


def discover_collectors() -> dict[str, Path]:
    """Discover available collectors by scanning collectors/*/collector.py."""
    discovered: dict[str, Path] = {}
    if not COLLECTORS_DIR.exists():
        return discovered

    for item in sorted(COLLECTORS_DIR.iterdir()):
        if not item.is_dir():
            continue
        collector_file = item / "collector.py"
        if collector_file.exists():
            discovered[item.name] = item
    return discovered


def load_profile(path: Path) -> dict[str, Any]:
    """Load profile from JSON (default) or YAML when PyYAML is installed."""
    if not path.exists():
        raise FileNotFoundError(f"Profile file not found: {path}")

    if path.suffix.lower() in {".json"}:
        return json.loads(path.read_text(encoding="utf-8"))

    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "YAML profile requires PyYAML. Install it with `pip install pyyaml` "
                "or use JSON profile."
            ) from exc
        data = yaml.safe_load(path.read_text(encoding="utf-8"))  # type: ignore[attr-defined]
        return data or {}

    raise ValueError(f"Unsupported profile format: {path.suffix}")


def _normalize_slug_list(raw: Any, field_name: str) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
        raise ValueError(f"Profile field '{field_name}' must be a list of strings")
    return [item.strip() for item in raw if item.strip()]


def resolve_target_slugs(profile: dict[str, Any], available: dict[str, Path]) -> list[str]:
    """Resolve final collector list from profile and discovered collectors."""
    mode = str(profile.get("run_mode", "enabled_only")).strip().lower()
    enabled = set(_normalize_slug_list(profile.get("enabled"), "enabled"))
    disabled = set(_normalize_slug_list(profile.get("disabled"), "disabled"))
    available_slugs = set(available.keys())

    unknown_enabled = sorted(enabled - available_slugs)
    unknown_disabled = sorted(disabled - available_slugs)
    if unknown_enabled:
        raise ValueError(f"Unknown collectors in 'enabled': {', '.join(unknown_enabled)}")
    if unknown_disabled:
        raise ValueError(f"Unknown collectors in 'disabled': {', '.join(unknown_disabled)}")

    if mode == "enabled_only":
        selected = enabled - disabled
    elif mode == "all_except_disabled":
        selected = available_slugs - disabled
        if enabled:
            selected = selected & enabled if profile.get("enabled_as_allowlist", False) else selected
    else:
        raise ValueError("run_mode must be 'enabled_only' or 'all_except_disabled'")

    return sorted(selected)


def _run_one_collector(
    slug: str,
    collector_dir: Path,
    timeout_seconds: int,
    env_overrides: dict[str, str],
) -> CollectorResult:
    start = time.perf_counter()
    env = os.environ.copy()
    env.update(env_overrides)

    cmd = [sys.executable, "collector.py"]
    try:
        proc = subprocess.run(  # noqa: S603
            cmd,
            cwd=str(collector_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        duration = time.perf_counter() - start
        return CollectorResult(
            slug=slug,
            returncode=proc.returncode,
            duration_seconds=duration,
            stdout=proc.stdout,
            stderr=proc.stderr,
            timed_out=False,
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.perf_counter() - start
        return CollectorResult(
            slug=slug,
            returncode=124,
            duration_seconds=duration,
            stdout=exc.stdout or "",
            stderr=exc.stderr or f"Collector timed out after {timeout_seconds}s",
            timed_out=True,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run SecLens collectors by profile.")
    parser.add_argument(
        "--profile",
        default="profiles/default.json",
        help="Path to profile file (JSON, or YAML when PyYAML is installed).",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List discovered collectors and exit.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Resolve and print target collectors without executing.",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop scheduling new collectors after first failure.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    available = discover_collectors()

    if args.list:
        print("Discovered collectors:")
        for slug in sorted(available.keys()):
            print(f"- {slug}")
        return 0

    profile_path = (ROOT / args.profile).resolve() if not Path(args.profile).is_absolute() else Path(args.profile)
    profile = load_profile(profile_path)
    target_slugs = resolve_target_slugs(profile, available)

    concurrency = int(profile.get("concurrency", 1))
    timeout_seconds = int(profile.get("timeout_seconds", 300))
    continue_on_error = bool(profile.get("continue_on_error", True))
    env_overrides = {
        str(k): str(v)
        for k, v in dict(profile.get("env", {})).items()
        if isinstance(k, str) and v is not None
    }

    if args.dry_run or bool(profile.get("dry_run", False)):
        print(f"Profile: {profile_path}")
        print(f"Run mode: {profile.get('run_mode', 'enabled_only')}")
        print(f"Collectors to run ({len(target_slugs)}):")
        for slug in target_slugs:
            print(f"- {slug}")
        return 0

    if not target_slugs:
        print("No collectors selected. Exiting.")
        return 0

    print(f"Profile: {profile_path}")
    print(f"Running {len(target_slugs)} collectors (concurrency={concurrency}, timeout={timeout_seconds}s)")

    failures = 0
    results: list[CollectorResult] = []
    started = 0

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as executor:
        future_map = {}
        for slug in target_slugs:
            if args.fail_fast and failures > 0:
                break
            future = executor.submit(
                _run_one_collector,
                slug,
                available[slug],
                timeout_seconds,
                env_overrides,
            )
            future_map[future] = slug
            started += 1

        for future in as_completed(future_map):
            result = future.result()
            results.append(result)
            status = "OK" if result.returncode == 0 else "FAIL"
            print(f"[{status}] {result.slug} ({result.duration_seconds:.1f}s)")
            if result.stdout.strip():
                print(result.stdout.strip())
            if result.stderr.strip():
                print(result.stderr.strip(), file=sys.stderr)

            if result.returncode != 0:
                failures += 1
                if not continue_on_error:
                    print("Aborting because continue_on_error=false")
                    break

    succeeded = sum(1 for item in results if item.returncode == 0)
    failed = sum(1 for item in results if item.returncode != 0)
    timed_out = sum(1 for item in results if item.timed_out)

    print("---- Summary ----")
    print(f"Scheduled: {started}")
    print(f"Finished: {len(results)}")
    print(f"Succeeded: {succeeded}")
    print(f"Failed: {failed}")
    print(f"Timed out: {timed_out}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
