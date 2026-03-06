"""VulDB vulnerability database collector.

Fetches recent vulnerabilities from VulDB RSS feed and pushes them
to a SecLens server. Fully standalone - no SecLens app dependencies.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 1 hour (3600s)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Sequence

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.time_helpers import parse_first, now_utc_iso

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")
FEED_URL = os.environ.get("VULDB_FEED_URL", "https://vuldb.com/?rss.recent")
SOURCE_SLUG = "vuldb"
USER_AGENT = "SeclensCollector/2.0 (vuldb)"
REQUEST_TIMEOUT = 30
DEFAULT_LIMIT = 20
STATE_FILE_NAME = ".cursor"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class FeedEntry:
    """Represents a single entry from the VulDB RSS feed."""
    entry_id: str
    title: str
    link: str
    description: str | None
    published_at: str | None
    fetched_at: str
    raw_pub_date: str | None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_vuldb_id(link: str) -> str:
    """Extract VulDB ID from the URL."""
    match = re.search(r'id\.(\d+)', link) or re.search(r'/(\d+)', link.split('/')[-1])
    if match:
        return f"vuldb_{match.group(1)}"
    return f"vuldb_{hashlib.md5(link.encode()).hexdigest()[:12]}"


def _extract_cve_ids(text: str) -> list[str]:
    """Extract CVE IDs from text."""
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    return re.findall(cve_pattern, text.upper())


# ---------------------------------------------------------------------------
# Cursor helpers
# ---------------------------------------------------------------------------


def _cursor_path() -> Path:
    return Path(__file__).resolve().with_name(STATE_FILE_NAME)


def _load_cursor() -> datetime | None:
    try:
        raw = _cursor_path().read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        logger.warning("Invalid cursor value '%s'; ignoring", raw)
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _save_cursor(value: datetime) -> None:
    value = value.astimezone(timezone.utc)
    _cursor_path().write_text(value.isoformat(), encoding="utf-8")


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


def fetch_feed(feed_url: str = FEED_URL) -> list[FeedEntry]:
    """Fetch and parse the VulDB RSS feed."""
    logger.info("Fetching feed: %s", feed_url)
    resp = requests.get(
        feed_url,
        timeout=REQUEST_TIMEOUT,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/rss+xml, application/xml, text/xml;q=0.9, */*;q=0.8",
        },
    )
    resp.raise_for_status()
    text = resp.text.lstrip()

    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("Failed to parse VulDB RSS feed") from exc

    entries: list[FeedEntry] = []
    for item in root.findall(".//item"):
        link = (item.findtext("link") or "").strip()
        if not link:
            continue

        entry_id = _extract_vuldb_id(link)
        title = (item.findtext("title") or "").strip()
        description = (item.findtext("description") or "").strip()
        fetched_at = now_utc_iso()
        raw_pub_date = item.findtext("pubDate")

        published_at = parse_first(
            [(raw_pub_date, "item.pubDate")],
            default_tz="UTC",
        )

        entries.append(
            FeedEntry(
                entry_id=entry_id,
                title=title,
                link=link,
                description=description,
                published_at=published_at,
                fetched_at=fetched_at,
                raw_pub_date=raw_pub_date.strip() if isinstance(raw_pub_date, str) else None,
            )
        )
    logger.info("Fetched %d items", len(entries))
    return entries


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(entry: FeedEntry) -> dict:
    """Convert a VulDB feed entry to a SecLens bulletin dict."""
    published_at = parse_first(
        [(entry.published_at, "entry.published_at"), (entry.raw_pub_date, "feed.pubDate")],
        default_tz="UTC",
    )

    cve_ids = _extract_cve_ids(entry.title + " " + (entry.description or ""))

    labels: list[str] = []
    topics = ["official_bulletin"]
    if cve_ids:
        topics.append("cve")
        for cve_id in cve_ids:
            if cve_id not in labels:
                labels.append(cve_id)

    extra: dict[str, object] = {
        "raw_pub_date": entry.raw_pub_date,
    }

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": entry.entry_id,
            "origin_url": entry.link,
        },
        "content": {
            "title": entry.title,
            "summary": entry.description,
            "body_text": entry.description,
            "published_at": published_at,
            "language": "en",
        },
        "severity": None,
        "fetched_at": entry.fetched_at,
        "labels": labels,
        "topics": topics,
        "extra": extra or None,
        "raw": {
            "entry": {
                "title": entry.title,
                "description": entry.description,
                "link": entry.link,
                "pubDate": entry.raw_pub_date,
            }
        },
    }


# ---------------------------------------------------------------------------
# Push
# ---------------------------------------------------------------------------


def push_to_seclens(bulletins: list[dict]) -> dict:
    """Submit bulletins to the SecLens Ingest API."""
    endpoint = f"{SECLENS_URL}/v1/ingest/bulletins"
    logger.info("Pushing %d bulletins to %s", len(bulletins), endpoint)

    resp = requests.post(
        endpoint,
        json=bulletins,
        headers={
            "Authorization": f"Bearer {SECLENS_TOKEN}",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    result = resp.json()
    logger.info(
        "Server response: accepted=%s, duplicates=%s",
        result.get("accepted"),
        result.get("duplicates"),
    )
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    if not SECLENS_URL:
        logger.error("SECLENS_URL environment variable is required")
        sys.exit(1)
    if not SECLENS_TOKEN:
        logger.error("SECLENS_TOKEN environment variable is required")
        sys.exit(1)

    entries = fetch_feed()

    # Apply cursor filtering
    cursor = _load_cursor()
    if cursor:
        entries = [
            e for e in entries
            if e.published_at and datetime.fromisoformat(e.published_at) > cursor
        ]

    entries.sort(key=lambda e: e.published_at or "")
    if DEFAULT_LIMIT and len(entries) > DEFAULT_LIMIT:
        entries = entries[-DEFAULT_LIMIT:]

    bulletins: list[dict] = []
    latest_dt: datetime | None = cursor
    for entry in entries:
        try:
            bulletin = normalize(entry)
            bulletins.append(bulletin)
            if entry.published_at:
                entry_dt = datetime.fromisoformat(entry.published_at)
                if latest_dt is None or entry_dt > latest_dt:
                    latest_dt = entry_dt
        except Exception as exc:
            logger.exception("Failed to normalize VulDB entry %s: %s", entry.entry_id, exc)

    if not bulletins:
        logger.info("No items to push")
        return

    result = push_to_seclens(bulletins)

    if latest_dt and bulletins:
        _save_cursor(latest_dt)

    print(
        f"Done: {len(bulletins)} fetched, "
        f"{result.get('accepted', 0)} accepted, "
        f"{result.get('duplicates', 0)} duplicates"
    )


if __name__ == "__main__":
    main()
