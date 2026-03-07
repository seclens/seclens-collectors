#!/usr/bin/env python3
"""Run collectors by centralized profile configuration with schedule awareness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests


ROOT = Path(__file__).resolve().parent
COLLECTORS_DIR = ROOT / "collectors"
DEFAULT_INTERVAL_MINUTES = 60
DEFAULT_MIN_INTERVAL_MINUTES = 30
DEFAULT_STATE_FILE = ".state/scheduler_state.json"
ANCHOR_BASE = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
ALLOWED_PLUGIN_ENV_KEYS = {
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
}


@dataclass(frozen=True)
class CollectorSchedule:
    slug: str
    interval_minutes: int
    anchor_utc: datetime
    next_due_at: datetime
    due_now: bool
    source: str
    env_overrides: dict[str, str]


@dataclass(frozen=True)
class CollectorResult:
    slug: str
    returncode: int
    duration_seconds: float
    stdout: str
    stderr: str
    timed_out: bool
    started_at: datetime
    finished_at: datetime


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


def _parse_utc_datetime(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _to_utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _env_name_for_slug(slug: str, suffix: str) -> str:
    normalized = "".join(ch if ch.isalnum() else "_" for ch in slug.upper())
    return f"COLLECTOR_{normalized}_{suffix}"


def _parse_interval_from_comment(config_file: Path) -> int | None:
    if not config_file.exists():
        return None
    pattern = re.compile(r"recommended\s+schedule\s*:\s*every\s+(\d+)\s+(minute|minutes|hour|hours)", re.IGNORECASE)
    for line in config_file.read_text(encoding="utf-8").splitlines():
        match = pattern.search(line)
        if not match:
            continue
        value = int(match.group(1))
        unit = match.group(2).lower()
        if unit.startswith("hour"):
            return value * 60
        return value
    return None


def _parse_manifest_interval_minutes(manifest_file: Path) -> int | None:
    """Parse manifest.schedule (seconds) and convert it to minutes."""
    if not manifest_file.exists():
        return None
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    raw_schedule = manifest.get("schedule")
    if raw_schedule is None:
        return None

    try:
        schedule_seconds = int(str(raw_schedule).strip())
    except (TypeError, ValueError):
        return None

    if schedule_seconds <= 0:
        return None
    if schedule_seconds % 60 != 0:
        return None
    return schedule_seconds // 60


def _default_anchor_for_slug(slug: str, interval_minutes: int) -> datetime:
    digest = hashlib.sha1(slug.encode("utf-8")).hexdigest()
    slot = int(digest, 16) % interval_minutes
    return ANCHOR_BASE + timedelta(minutes=slot)


def _compute_next_due(anchor: datetime, interval_minutes: int, reference: datetime, *, inclusive: bool) -> datetime:
    step_seconds = interval_minutes * 60
    if reference <= anchor:
        return anchor

    delta = (reference - anchor).total_seconds()
    multiples = int(delta // step_seconds)
    candidate = anchor + timedelta(seconds=multiples * step_seconds)
    if candidate < reference or (candidate == reference and not inclusive):
        candidate += timedelta(seconds=step_seconds)
    return candidate


def _load_state(state_path: Path) -> dict[str, Any]:
    if not state_path.exists():
        return {}
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _save_state(state_path: Path, state: dict[str, Any]) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = state_path.with_suffix(state_path.suffix + ".tmp")
    temp_path.write_text(json.dumps(state, ensure_ascii=True, indent=2, sort_keys=True), encoding="utf-8")
    temp_path.replace(state_path)


def _resolve_schedule(
    slug: str,
    collector_dir: Path,
    profile: dict[str, Any],
    state_entry: dict[str, Any] | None,
    now_utc: datetime,
) -> CollectorSchedule:
    min_interval = int(profile.get("min_interval_minutes", DEFAULT_MIN_INTERVAL_MINUTES))
    default_interval = int(profile.get("default_interval_minutes", DEFAULT_INTERVAL_MINUTES))
    schedule_overrides = profile.get("schedule_overrides", {})
    override = schedule_overrides.get(slug, {}) if isinstance(schedule_overrides, dict) else {}

    interval_source = "default"
    interval = default_interval

    manifest_interval = _parse_manifest_interval_minutes(collector_dir / "manifest.json")
    if manifest_interval is not None:
        interval = manifest_interval
        interval_source = "manifest"

    config_interval = _parse_interval_from_comment(collector_dir / "config.example.yaml")
    if config_interval is not None and manifest_interval is None:
        interval = config_interval
        interval_source = "collector-config"

    if isinstance(override, dict) and override.get("interval_minutes") is not None:
        interval = int(override["interval_minutes"])
        interval_source = "profile-override"

    env_interval = os.environ.get(_env_name_for_slug(slug, "INTERVAL_MINUTES"))
    if env_interval:
        interval = int(env_interval)
        interval_source = "env-override"

    if interval < min_interval:
        interval = min_interval
        interval_source += f"+min({min_interval})"

    anchor_source = "deterministic-default"
    anchor = _default_anchor_for_slug(slug, interval)

    default_anchor_raw = profile.get("default_anchor_utc")
    if isinstance(default_anchor_raw, str) and default_anchor_raw.strip():
        anchor = _parse_utc_datetime(default_anchor_raw)
        anchor_source = "profile-default-anchor"

    if isinstance(override, dict) and override.get("anchor_utc"):
        anchor = _parse_utc_datetime(str(override["anchor_utc"]))
        anchor_source = "profile-override"

    env_anchor = os.environ.get(_env_name_for_slug(slug, "ANCHOR_UTC"))
    if env_anchor:
        anchor = _parse_utc_datetime(env_anchor)
        anchor_source = "env-override"

    next_due = _compute_next_due(anchor, interval, now_utc, inclusive=True)

    if state_entry:
        state_interval = state_entry.get("interval_minutes")
        state_anchor_raw = state_entry.get("anchor_utc")
        state_next_raw = state_entry.get("next_due_at")
        if state_interval == interval and isinstance(state_anchor_raw, str) and isinstance(state_next_raw, str):
            try:
                state_anchor = _parse_utc_datetime(state_anchor_raw)
                if state_anchor == anchor:
                    next_due = _parse_utc_datetime(state_next_raw)
            except ValueError:
                pass

    plugin_env: dict[str, str] = {}
    if isinstance(override, dict):
        raw_env = override.get("env", {})
        if raw_env is not None:
            if not isinstance(raw_env, dict):
                raise ValueError(f"schedule_overrides.{slug}.env must be an object")
            for key, value in raw_env.items():
                if not isinstance(key, str):
                    raise ValueError(f"schedule_overrides.{slug}.env keys must be strings")
                if value is None:
                    continue
                if key not in ALLOWED_PLUGIN_ENV_KEYS:
                    allowed = ", ".join(sorted(ALLOWED_PLUGIN_ENV_KEYS))
                    raise ValueError(
                        f"Unsupported env key in schedule_overrides.{slug}.env: '{key}'. "
                        f"Allowed keys: {allowed}"
                    )
                plugin_env[str(key)] = str(value)

    source = f"interval={interval_source},anchor={anchor_source}"
    return CollectorSchedule(
        slug=slug,
        interval_minutes=interval,
        anchor_utc=anchor,
        next_due_at=next_due,
        due_now=now_utc >= next_due,
        source=source,
        env_overrides=plugin_env,
    )


def _run_one_collector(
    slug: str,
    collector_dir: Path,
    timeout_seconds: int,
    env_overrides: dict[str, str],
) -> CollectorResult:
    start_perf = time.perf_counter()
    started_at = datetime.now(timezone.utc)

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
        finished_at = datetime.now(timezone.utc)
        duration = time.perf_counter() - start_perf
        return CollectorResult(
            slug=slug,
            returncode=proc.returncode,
            duration_seconds=duration,
            stdout=proc.stdout,
            stderr=proc.stderr,
            timed_out=False,
            started_at=started_at,
            finished_at=finished_at,
        )
    except subprocess.TimeoutExpired as exc:
        finished_at = datetime.now(timezone.utc)
        duration = time.perf_counter() - start_perf
        return CollectorResult(
            slug=slug,
            returncode=124,
            duration_seconds=duration,
            stdout=exc.stdout or "",
            stderr=exc.stderr or f"Collector timed out after {timeout_seconds}s",
            timed_out=True,
            started_at=started_at,
            finished_at=finished_at,
        )


def _emit_empty_heartbeat(
    *,
    slug: str,
    result: CollectorResult,
    env: dict[str, str],
    timeout_seconds: int,
) -> None:
    seclens_url = (env.get("SECLENS_URL") or "").strip().rstrip("/")
    seclens_token = (env.get("SECLENS_TOKEN") or "").strip()
    if not seclens_url or not seclens_token:
        return

    status = "ok"
    if result.timed_out:
        status = "timeout"
    elif result.returncode != 0:
        status = "failed"

    headers = {
        "Authorization": f"Bearer {seclens_token}",
        "Content-Type": "application/json",
        "X-SecLens-Source-Slug": slug,
        "X-SecLens-Heartbeat-Status": status,
    }
    endpoint = f"{seclens_url}/v1/ingest/bulletins"

    try:
        resp = requests.post(endpoint, json=[], headers=headers, timeout=timeout_seconds)
        resp.raise_for_status()
    except Exception as exc:
        print(f"[HEARTBEAT-FAIL] {slug}: {exc}", file=sys.stderr)
    else:
        print(f"[HEARTBEAT-OK] {slug}: status={status}")


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
        help="Resolve and print target collectors and scheduling decisions without executing.",
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
    emit_heartbeat = bool(profile.get("emit_empty_heartbeat", True))
    heartbeat_timeout_seconds = int(profile.get("heartbeat_timeout_seconds", 15))
    env_overrides = {
        str(k): str(v)
        for k, v in dict(profile.get("env", {})).items()
        if isinstance(k, str) and v is not None
    }

    state_file_raw = str(profile.get("state_file", DEFAULT_STATE_FILE))
    state_path = (ROOT / state_file_raw).resolve() if not Path(state_file_raw).is_absolute() else Path(state_file_raw)
    state = _load_state(state_path)

    now_utc = datetime.now(timezone.utc)
    schedules: dict[str, CollectorSchedule] = {}
    due_slugs: list[str] = []

    for slug in target_slugs:
        schedule = _resolve_schedule(
            slug,
            available[slug],
            profile,
            state.get(slug) if isinstance(state.get(slug), dict) else None,
            now_utc,
        )
        schedules[slug] = schedule
        if schedule.due_now:
            due_slugs.append(slug)

    if args.dry_run or bool(profile.get("dry_run", False)):
        print(f"Profile: {profile_path}")
        print(f"Run mode: {profile.get('run_mode', 'enabled_only')}")
        print(f"State file: {state_path}")
        print(f"Collectors selected ({len(target_slugs)}):")
        for slug in target_slugs:
            schedule = schedules[slug]
            status = "DUE" if schedule.due_now else "SKIP"
            print(
                f"- {slug}: {status}, interval={schedule.interval_minutes}m, "
                f"anchor={_to_utc_iso(schedule.anchor_utc)}, next_due={_to_utc_iso(schedule.next_due_at)}"
            )
        print(f"Collectors due now ({len(due_slugs)}):")
        for slug in due_slugs:
            print(f"- {slug}")
        return 0

    if not target_slugs:
        print("No collectors selected. Exiting.")
        return 0

    if not due_slugs:
        print(f"Profile: {profile_path}")
        print(f"No collectors due at {_to_utc_iso(now_utc)}. Exiting.")
        return 0

    print(f"Profile: {profile_path}")
    print(f"State file: {state_path}")
    print(
        f"Running {len(due_slugs)}/{len(target_slugs)} due collectors "
        f"(concurrency={concurrency}, timeout={timeout_seconds}s)"
    )

    failures = 0
    results: list[CollectorResult] = []
    started = 0

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as executor:
        future_map = {}
        for slug in due_slugs:
            if args.fail_fast and failures > 0:
                break
            future = executor.submit(
                _run_one_collector,
                slug,
                available[slug],
                timeout_seconds,
                {**env_overrides, **schedules[slug].env_overrides},
            )
            future_map[future] = slug
            started += 1
            plugin_env_keys = sorted(schedules[slug].env_overrides.keys())
            if plugin_env_keys:
                print(f"[ENV] {slug}: plugin env keys={', '.join(plugin_env_keys)}")

        for future in as_completed(future_map):
            result = future.result()
            results.append(result)
            merged_env = {**env_overrides, **schedules[result.slug].env_overrides}

            if emit_heartbeat:
                _emit_empty_heartbeat(
                    slug=result.slug,
                    result=result,
                    env=merged_env,
                    timeout_seconds=heartbeat_timeout_seconds,
                )

            status = "OK" if result.returncode == 0 else "FAIL"
            print(f"[{status}] {result.slug} ({result.duration_seconds:.1f}s)")
            if result.stdout.strip():
                print(result.stdout.strip())
            if result.stderr.strip():
                print(result.stderr.strip(), file=sys.stderr)

            schedule = schedules[result.slug]
            next_due = _compute_next_due(
                schedule.anchor_utc,
                schedule.interval_minutes,
                result.finished_at,
                inclusive=False,
            )
            state[result.slug] = {
                "interval_minutes": schedule.interval_minutes,
                "anchor_utc": _to_utc_iso(schedule.anchor_utc),
                "next_due_at": _to_utc_iso(next_due),
                "last_run_started_at": _to_utc_iso(result.started_at),
                "last_run_finished_at": _to_utc_iso(result.finished_at),
                "last_status": "success" if result.returncode == 0 else "failed",
                "last_returncode": result.returncode,
                "schedule_source": schedule.source,
            }

            if result.returncode != 0:
                failures += 1
                if not continue_on_error:
                    print("Aborting because continue_on_error=false")
                    break

    _save_state(state_path, state)

    succeeded = sum(1 for item in results if item.returncode == 0)
    failed = sum(1 for item in results if item.returncode != 0)
    timed_out = sum(1 for item in results if item.timed_out)

    print("---- Summary ----")
    print(f"Selected: {len(target_slugs)}")
    print(f"Due: {len(due_slugs)}")
    print(f"Scheduled: {started}")
    print(f"Finished: {len(results)}")
    print(f"Succeeded: {succeeded}")
    print(f"Failed: {failed}")
    print(f"Timed out: {timed_out}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
