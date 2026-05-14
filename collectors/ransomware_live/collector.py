"""Ransomware.live recent victims collector.

Fetches recently discovered ransomware victims from the Ransomware.live API
and pushes them to a SecLens server.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    export RANSOMWARE_LIVE_API_KEY="your-ransomware-live-api-key"
    python collector.py

Schedule: recommended every 1 hour (3600s)
"""
from __future__ import annotations

import logging
import os
import re
import sys
from pathlib import Path
from typing import Any

import requests

try:
    from shared.manifest import load_manifest_for_slug
    from shared.time_helpers import now_utc_iso, parse_first
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from shared.manifest import load_manifest_for_slug
    from shared.time_helpers import now_utc_iso, parse_first


SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")

SOURCE_SLUG = "ransomware_live"
API_URL = os.environ.get(
    "RANSOMWARE_LIVE_API_URL",
    "https://api-pro.ransomware.live/victims/recent?order=discovered",
)
API_KEY = os.environ.get("RANSOMWARE_LIVE_API_KEY", "").strip()
USER_AGENT = "SeclensCollector/2.0 (ransomware_live)"
REQUEST_TIMEOUT = 30
STATE_FILE_NAME = ".cursor"
BATCH_SIZE = int(os.environ.get("RANSOMWARE_LIVE_BATCH_SIZE", "50"))
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(
    SOURCE_SLUG,
    repo_root=Path(__file__).resolve().parents[2],
)

REQUEST_HEADERS = {
    "Accept": "application/json",
    "User-Agent": USER_AGENT,
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


def _trim(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = " ".join(value.split()).strip()
    return cleaned or None


def _slugify_label_value(value: str | None) -> str | None:
    cleaned = _trim(value)
    if not cleaned:
        return None
    slug = re.sub(r"[^a-z0-9]+", "-", cleaned.lower()).strip("-")
    return slug or None


def _state_file_path() -> Path:
    return Path(__file__).resolve().parent / STATE_FILE_NAME


def load_cursor() -> str | None:
    path = _state_file_path()
    if not path.exists():
        return None
    value = path.read_text(encoding="utf-8").strip()
    return value or None


def save_cursor(cursor: str) -> None:
    _state_file_path().write_text(cursor.strip(), encoding="utf-8")


def fetch_items() -> list[dict[str, Any]]:
    headers = dict(REQUEST_HEADERS)
    headers["X-API-KEY"] = API_KEY

    response = requests.get(
        API_URL,
        timeout=REQUEST_TIMEOUT,
        headers=headers,
    )
    response.raise_for_status()

    payload = response.json()
    victims = payload.get("victims", [])
    if not isinstance(victims, list):
        logger.warning("Unexpected API shape: 'victims' is not a list")
        return []

    logger.info("Fetched %d victims from Ransomware.live", len(victims))
    return [item for item in victims if isinstance(item, dict)]


def _build_body_text(item: dict[str, Any]) -> str | None:
    lines: list[str] = []
    victim = _trim(item.get("victim"))
    group = _trim(item.get("group"))
    activity = _trim(item.get("activity"))
    country = _trim(item.get("country"))
    website = _trim(item.get("website"))
    attackdate = _trim(item.get("attackdate"))
    discovered = _trim(item.get("discovered"))
    description = _trim(item.get("description"))
    press = _trim(item.get("press"))
    post_url = _trim(item.get("post_url"))
    permalink = _trim(item.get("permalink"))

    if victim:
        lines.append(f"Victim: {victim}")
    if group:
        lines.append(f"Ransomware group: {group}")
    if activity:
        lines.append(f"Sector: {activity}")
    if country:
        lines.append(f"Country: {country}")
    if website:
        lines.append(f"Website: {website}")
    if attackdate:
        lines.append(f"Attack date: {attackdate}")
    if discovered:
        lines.append(f"Discovered: {discovered}")
    if description and description.upper() != "N/A":
        lines.extend(["", description])
    if press:
        lines.extend(["", f"Press coverage: {press}"])
    if post_url:
        lines.append(f"Leak post: {post_url}")
    if permalink:
        lines.append(f"Permalink: {permalink}")

    return "\n".join(lines).strip() or None


def normalize(item: dict[str, Any]) -> dict | None:
    external_id = _trim(item.get("id"))
    victim = _trim(item.get("victim"))
    group = _trim(item.get("group"))

    if not external_id:
        logger.warning("Skipping item without id: victim=%s group=%s", victim, group)
        return None

    published_at = parse_first(
        [
            (item.get("discovered"), "item.discovered"),
            (item.get("attackdate"), "item.attackdate"),
        ],
        default_tz="UTC",
    )

    description = _trim(item.get("description"))
    summary = description if description and description.upper() != "N/A" else None
    origin_url = _trim(item.get("permalink")) or _trim(item.get("post_url"))
    title_parts = [part for part in [victim, f"by {group}" if group else None] if part]
    title = " ".join(title_parts) if title_parts else f"Ransomware victim {external_id}"

    labels: list[str] = ["source:ransomware-live", "type:ransomware-victim"]

    group_label = _slugify_label_value(group)
    if group_label:
        labels.append(f"group:{group_label}")

    country = _trim(item.get("country"))
    if country:
        labels.append(f"country:{country.lower()}")

    activity = _slugify_label_value(item.get("activity"))
    if activity and activity != "not-found":
        labels.append(f"activity:{activity}")

    if _trim(item.get("press")):
        labels.append("has:press")
    if _trim(item.get("post_url")):
        labels.append("has:leak-post")
    if _trim(item.get("screenshot")):
        labels.append("has:screenshot")
    if item.get("duplicates"):
        labels.append("has:duplicates")
    if item.get("infostealer") not in ("", None, {}):
        labels.append("has:infostealer")

    duplicates = item.get("duplicates")
    infostealer = item.get("infostealer")
    extra: dict[str, Any] = {
        "group": group,
        "website": _trim(item.get("website")),
        "country": country,
        "activity": _trim(item.get("activity")),
        "post_url": _trim(item.get("post_url")),
        "permalink": _trim(item.get("permalink")),
        "press": _trim(item.get("press")),
        "screenshot": _trim(item.get("screenshot")),
        "attack_date": parse_first([(item.get("attackdate"), "item.attackdate")], default_tz="UTC"),
        "discovered_at": published_at,
        "duplicate_count": len(duplicates) if isinstance(duplicates, list) else 0,
    }
    if duplicates:
        extra["duplicates"] = duplicates
    if infostealer not in ("", None, {}):
        extra["infostealer"] = infostealer
    if item.get("extrainfos") not in ("", None, {}):
        extra["extra_infos"] = item.get("extrainfos")

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": external_id,
            "origin_url": origin_url,
            "manifest": MANIFEST,
            "manifest_hash": MANIFEST_HASH,
            "manifest_version": MANIFEST_VERSION,
        },
        "content": {
            "title": title[:500],
            "summary": summary,
            "body_text": _build_body_text(item),
            "published_at": published_at,
            "language": "en",
        },
        "severity": None,
        "fetched_at": now_utc_iso(),
        "labels": labels,
        "topics": ["threat_intelligence", "ransomware"],
        "extra": extra,
        "raw": item,
    }


def _select_fresh_items(items: list[dict[str, Any]], cursor: str | None) -> list[dict[str, Any]]:
    if not cursor:
        return items

    fresh_items: list[dict[str, Any]] = []
    for item in items:
        item_id = _trim(item.get("id"))
        if item_id == cursor:
            break
        fresh_items.append(item)
    return fresh_items


def push_to_seclens(bulletins: list[dict]) -> dict:
    endpoint = f"{SECLENS_URL}/v1/ingest/bulletins"
    headers = {
        "Authorization": f"Bearer {SECLENS_TOKEN}",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }

    accepted = 0
    duplicates = 0

    for i in range(0, len(bulletins), BATCH_SIZE):
        chunk = bulletins[i : i + BATCH_SIZE]
        resp = requests.post(endpoint, json=chunk, timeout=REQUEST_TIMEOUT, headers=headers)
        if resp.status_code >= 400:
            logger.error(
                "Push failed for batch %s-%s: %s %s",
                i,
                i + len(chunk),
                resp.status_code,
                resp.text[:400],
            )
            resp.raise_for_status()
        payload = resp.json()
        accepted += int(payload.get("accepted", 0) or 0)
        duplicates += int(payload.get("duplicates", 0) or 0)

    logger.info("Push done: accepted=%s duplicates=%s", accepted, duplicates)
    return {"accepted": accepted, "duplicates": duplicates}


def main() -> None:
    if not SECLENS_URL:
        logger.error("SECLENS_URL environment variable is required")
        sys.exit(1)
    if not SECLENS_TOKEN:
        logger.error("SECLENS_TOKEN environment variable is required")
        sys.exit(1)
    if not API_KEY:
        logger.error("RANSOMWARE_LIVE_API_KEY environment variable is required")
        sys.exit(1)

    items = fetch_items()
    if not items:
        logger.info("No victims fetched")
        return

    latest_cursor = _trim(items[0].get("id"))
    previous_cursor = load_cursor()
    fresh_items = _select_fresh_items(items, previous_cursor)

    if previous_cursor:
        logger.info(
            "Cursor loaded: %s, %d new candidate victims",
            previous_cursor,
            len(fresh_items),
        )

    bulletins: list[dict] = []
    for item in fresh_items:
        normalized = normalize(item)
        if normalized is not None:
            bulletins.append(normalized)

    if not bulletins:
        logger.info("No new victims to push")
        if latest_cursor:
            save_cursor(latest_cursor)
        return

    push_to_seclens(bulletins)
    if latest_cursor:
        save_cursor(latest_cursor)


if __name__ == "__main__":
    main()
