"""FreeBuf RSS community collector - standalone version.

Fetches security articles from the FreeBuf RSS feed and pushes them
to a SecLens server. Uses slug-based caching to avoid re-processing.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 30 minutes (1800s)
"""
from __future__ import annotations

import json
import logging
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.time_helpers import parse_first, now_utc_iso

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")
FEED_URL = os.environ.get("FREEBUF_FEED_URL", "https://www.freebuf.com/feed")

SOURCE_SLUG = "freebuf_community"
USER_AGENT = "SeclensCollector/2.0 (freebuf_community)"
REQUEST_TIMEOUT = 30
DEFAULT_TOPIC = "security_news"
DEFAULT_LIMIT = 40
MAX_CACHE_SIZE = 100

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

CACHE_FILE = Path(__file__).parent / ".cursor"


def _load_cache() -> set[str]:
    """Load cached slugs from JSON file."""
    try:
        with CACHE_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                items = data.get("slugs", [])
                if isinstance(items, list):
                    return set(items)
        return set()
    except (FileNotFoundError, json.JSONDecodeError):
        return set()


def _save_cache(slugs: set[str]) -> None:
    """Save slugs to cache, keeping only the latest MAX_CACHE_SIZE items."""
    slugs_list = list(slugs)[-MAX_CACHE_SIZE:]
    with CACHE_FILE.open("w", encoding="utf-8") as f:
        json.dump(
            {
                "slugs": slugs_list,
                "updated_at": now_utc_iso(),
            },
            f,
            indent=2,
            ensure_ascii=False,
        )


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


def fetch_feed(feed_url: str = FEED_URL) -> list[dict]:
    """Fetch and parse the FreeBuf RSS feed, return list of entry dicts."""
    logger.info("Fetching feed: %s", feed_url)
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "application/rss+xml, application/xml;q=0.9, */*;q=0.8",
        }
    )
    response = session.get(feed_url, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()

    try:
        root = ET.fromstring(response.text)
    except ET.ParseError as exc:
        raise ValueError("Failed to parse FreeBuf RSS feed") from exc

    entries: list[dict] = []
    for item in root.findall("./channel/item"):
        link = (item.findtext("link") or "").strip()
        if not link:
            continue
        title = (item.findtext("title") or link).strip()
        desc_node = item.findtext("description")
        description = desc_node.strip() if desc_node else None
        raw_pub_date = item.findtext("pubDate")

        published_at = parse_first(
            [(raw_pub_date, "item.pubDate")],
            default_tz="Asia/Shanghai",
        )

        categories = [
            (cat.text or "").strip()
            for cat in item.findall("category")
            if (cat.text or "").strip()
        ]
        slug = link.rstrip("/").rsplit("/", 1)[-1]

        entries.append(
            {
                "slug": slug or link,
                "title": title,
                "link": link,
                "description": description,
                "categories": categories,
                "published_at": published_at,
                "raw_pub_date": raw_pub_date.strip() if isinstance(raw_pub_date, str) else None,
            }
        )

    logger.info("Fetched %d items from feed", len(entries))
    return entries


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(entry: dict) -> dict:
    """Convert a feed entry dict to a SecLens bulletin dict."""
    labels = [f"category:{cat.lower()}" for cat in entry.get("categories", [])]
    extra: dict = {}
    if entry.get("categories"):
        extra["categories"] = entry["categories"]
    if entry.get("raw_pub_date"):
        extra["raw_pub_date"] = entry["raw_pub_date"]

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": entry["slug"],
            "origin_url": entry["link"],
        },
        "content": {
            "title": entry["title"],
            "summary": entry.get("description"),
            "body_text": entry.get("description"),
            "published_at": entry.get("published_at"),
            "language": "zh",
        },
        "severity": None,
        "fetched_at": now_utc_iso(),
        "labels": labels,
        "topics": [DEFAULT_TOPIC],
        "extra": extra or None,
        "raw": {
            "feed_entry": {
                "title": entry["title"],
                "link": entry["link"],
                "description": entry.get("description"),
                "categories": entry.get("categories", []),
                "published_at": entry.get("published_at"),
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
        result.get("accepted"), result.get("duplicates"),
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

    cached_slugs = _load_cache()
    logger.info("Cache loaded: %d slugs", len(cached_slugs))

    entries = fetch_feed()

    # Filter out cached items
    new_entries = []
    skipped = 0
    for entry in entries:
        if entry["slug"] in cached_slugs:
            skipped += 1
            continue
        new_entries.append(entry)

    logger.info("New entries: %d, Skipped (cached): %d", len(new_entries), skipped)

    # Apply limit
    if len(new_entries) > DEFAULT_LIMIT:
        new_entries = new_entries[:DEFAULT_LIMIT]

    bulletins = []
    for entry in new_entries:
        try:
            bulletin = normalize(entry)
            bulletins.append(bulletin)
        except Exception as e:
            logger.error("Failed to normalize entry %s: %s", entry.get("slug"), e)

    if not bulletins:
        logger.info("No new items to push")
        return

    # Update cache
    new_slugs = {e["slug"] for e in new_entries}
    updated_cache = cached_slugs | new_slugs
    _save_cache(updated_cache)
    logger.info("Cache updated: %d slugs", len(updated_cache))

    result = push_to_seclens(bulletins)
    print(
        f"Done: {len(bulletins)} fetched, "
        f"{result.get('accepted', 0)} accepted, "
        f"{result.get('duplicates', 0)} duplicates, "
        f"{skipped} skipped (cached)"
    )


if __name__ == "__main__":
    main()
