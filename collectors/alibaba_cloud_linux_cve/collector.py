"""Alibaba Cloud Linux CVE Vulnerabilities RSS collector.

Fetches CVE vulnerability notifications from Alibaba Cloud Linux Advisory
System (ALAS) and pushes them to a SecLens server. Fully standalone - no
SecLens app dependencies.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 2 hours (7200s)
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

try:
    from shared.manifest import load_manifest_for_slug
    from shared.time_helpers import now_utc_iso, parse_first
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from shared.manifest import load_manifest_for_slug
    from shared.time_helpers import now_utc_iso, parse_first

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")
SOURCE_SLUG = "alibaba_cloud_linux_cve"
USER_AGENT = "SeclensCollector/2.0 (alibaba_cloud_linux_cve)"
DEFAULT_FEED_URL = os.environ.get(
    "ALAS_CVE_FEED_URL",
    "https://alas.aliyuncs.com/api/rss/v1/cves/rss.xml",
)
REQUEST_TIMEOUT = 30
CACHE_FILE_NAME = ".cursor"
DEFAULT_LIMIT = 30
MAX_CACHE_SIZE = 200
MAX_RSS_ITEMS = 100
MAX_AGE_DAYS = 30
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)

# CVE ID pattern
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@dataclass
class FeedEntry:
    cve_id: str
    title: str
    link: str
    description: str | None
    published_at: str | None  # ISO 8601 string
    fetched_at: str  # ISO 8601 string
    raw_pub_date: str | None


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _cache_path() -> Path:
    return Path(__file__).resolve().with_name(CACHE_FILE_NAME)


def load_cache() -> set[str]:
    """Load cached CVE IDs from JSON file."""
    try:
        with _cache_path().open("r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                items = data.get("cve_ids", [])
                if isinstance(items, list):
                    return set(items)
        return set()
    except (FileNotFoundError, json.JSONDecodeError):
        return set()


def save_cache(cve_ids: set[str]) -> None:
    """Save CVE IDs to cache, keeping only the latest MAX_CACHE_SIZE items."""
    ids_list = list(cve_ids)[-MAX_CACHE_SIZE:]
    with _cache_path().open("w", encoding="utf-8") as f:
        json.dump(
            {
                "cve_ids": ids_list,
                "updated_at": now_utc_iso(),
            },
            f,
            indent=2,
        )


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

def fetch_feed(feed_url: str = DEFAULT_FEED_URL) -> Sequence[FeedEntry]:
    """Fetch and parse the ALAS CVE RSS feed."""
    logger.info("Fetching feed: %s", feed_url)
    response = requests.get(
        feed_url,
        timeout=REQUEST_TIMEOUT,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/rss+xml, application/xml;q=0.9, */*;q=0.8",
        },
    )
    response.raise_for_status()

    try:
        root = ET.fromstring(response.text)
    except ET.ParseError as exc:
        raise ValueError("Failed to parse ALAS CVE RSS feed") from exc

    entries: list[FeedEntry] = []
    fetched_at = now_utc_iso()
    fetched_dt = datetime.now(timezone.utc)  # noqa: UP017
    cutoff_date = fetched_dt - timedelta(days=MAX_AGE_DAYS)

    items = root.findall(".//item")[:MAX_RSS_ITEMS]
    logger.info("Processing %d RSS items (max: %d)", len(items), MAX_RSS_ITEMS)

    for item in items:
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        if not link or not title:
            continue

        # Extract CVE ID from title
        cve_match = CVE_PATTERN.search(title)
        if not cve_match:
            logger.warning("No CVE ID found in title: %s", title)
            continue
        cve_id = cve_match.group(0).upper()

        desc_node = item.findtext("description")
        description = desc_node.strip() if desc_node else None
        raw_pub_date = item.findtext("pubDate")

        published_at = parse_first(
            [(raw_pub_date, "item.pubDate")],
            default_tz="Asia/Shanghai",
        )

        # Filter old entries
        if published_at:
            try:
                pub_dt = datetime.fromisoformat(published_at)
                if pub_dt < cutoff_date:
                    logger.debug("Skipping old entry %s: %s", cve_id, published_at)
                    continue
            except ValueError:
                pass

        entries.append(
            FeedEntry(
                cve_id=cve_id,
                title=title,
                link=link,
                description=description,
                published_at=published_at,
                fetched_at=fetched_at,
                raw_pub_date=raw_pub_date.strip() if isinstance(raw_pub_date, str) else None,
            )
        )

    logger.info("Fetched %d valid entries within %d days", len(entries), MAX_AGE_DAYS)
    return entries


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------

def normalize(entry: FeedEntry) -> dict:
    """Convert a FeedEntry to a SecLens bulletin dict."""
    labels = ["vendor:alibaba", "type:cve", f"cve:{entry.cve_id.lower()}"]
    topics = ["vendor-update", "cve"]

    extra: dict[str, object] = {
        "cve_id": entry.cve_id,
    }
    if entry.raw_pub_date:
        extra["raw_pub_date"] = entry.raw_pub_date

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": entry.cve_id,
            "origin_url": entry.link,
            "manifest": MANIFEST,
            "manifest_hash": MANIFEST_HASH,
            "manifest_version": MANIFEST_VERSION,
        },
        "content": {
            "title": entry.title,
            "summary": entry.description,
            "body_text": entry.description,
            "published_at": entry.published_at,
            "language": "en",
        },
        "severity": None,
        "fetched_at": entry.fetched_at,
        "labels": labels,
        "topics": topics,
        "extra": extra,
        "raw": {
            "feed_entry": {
                "cve_id": entry.cve_id,
                "title": entry.title,
                "link": entry.link,
                "description": entry.description,
                "published_at": entry.published_at,
            }
        },
    }


# ---------------------------------------------------------------------------
# Collect
# ---------------------------------------------------------------------------

def collect(
    *,
    limit: int | None = None,
    force: bool = False,
) -> tuple[list[dict], dict]:
    """Collect CVE bulletins from ALAS RSS feed."""
    limit = limit or DEFAULT_LIMIT
    cached_ids = set() if force else load_cache()
    logger.info("Cache loaded: %d CVE IDs", len(cached_ids))

    entries = list(fetch_feed())
    entries.sort(
        key=lambda e: e.published_at or "",
        reverse=True,
    )

    # Filter out cached items
    new_entries: list[FeedEntry] = []
    skipped_count = 0
    for entry in entries:
        if entry.cve_id in cached_ids:
            skipped_count += 1
            continue
        new_entries.append(entry)

    logger.info("New entries: %d, Skipped (cached): %d", len(new_entries), skipped_count)

    # Apply limit
    if limit and len(new_entries) > limit:
        new_entries = new_entries[:limit]

    # Normalize to bulletins
    bulletins: list[dict] = []
    for entry in new_entries:
        try:
            bulletin = normalize(entry)
            bulletins.append(bulletin)
        except Exception as e:
            logger.error("Failed to normalize entry %s: %s", entry.cve_id, e)

    # Update cache
    if bulletins and not force:
        new_ids = {entry.cve_id for entry in new_entries}
        updated_cache = cached_ids | new_ids
        save_cache(updated_cache)
        logger.info("Cache updated: %d CVE IDs", len(updated_cache))

    stats = {
        "items_processed": len(entries),
        "items_created": len(bulletins),
        "items_skipped_cache": skipped_count,
    }

    return bulletins, stats


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

    bulletins, stats = collect()

    if not bulletins:
        logger.info("No items to push")
        logger.info("Done: processed=%d new=0", stats["items_processed"])
        return

    result = push_to_seclens(bulletins)
    logger.info(
        "Done: processed=%d fetched=%d accepted=%s duplicates=%s",
        stats["items_processed"],
        len(bulletins),
        result.get("accepted", 0),
        result.get("duplicates", 0),
    )


if __name__ == "__main__":
    main()
