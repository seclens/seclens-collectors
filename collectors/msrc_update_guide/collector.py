"""Microsoft Security Response Center (MSRC) update guide collector.

Fetches vulnerability revisions and advisories from the MSRC RSS feed
and pushes them to a SecLens server. Fully standalone - no SecLens app
dependencies.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 1 hour (3600s)
"""
from __future__ import annotations

import logging
import os
import sys
import xml.etree.ElementTree as ET
from collections.abc import Iterable
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
FEED_URL = os.environ.get(
    "MSRC_FEED_URL", "https://api.msrc.microsoft.com/update-guide/rss"
)
SOURCE_SLUG = "msrc_update_guide"
USER_AGENT = "SeclensCollector/2.0 (msrc_update_guide)"
REQUEST_TIMEOUT = 30
STATE_FILE_NAME = ".cursor"
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)

REQUEST_HEADERS = {
    "Accept": "application/rss+xml, application/xml;q=0.9, */*;q=0.8",
    "User-Agent": USER_AGENT,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_text(element: ET.Element | None) -> str | None:
    if element is None:
        return None
    text = (element.text or "").strip()
    return text or None


def _iter_items(channel: ET.Element) -> Iterable[ET.Element]:
    yield from channel.findall("item")


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


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


def _serialize_item(item: ET.Element) -> dict:
    guid_element = item.find("guid")
    categories = [
        _get_text(category)
        for category in item.findall("category")
        if _get_text(category)
    ]
    return {
        "title": _get_text(item.find("title")) or "",
        "link": _get_text(item.find("link")),
        "description": _get_text(item.find("description")),
        "guid": _get_text(guid_element),
        "guid_attributes": dict(guid_element.attrib) if guid_element is not None else {},
        "pub_date": _get_text(item.find("pubDate")),
        "categories": categories,
        "revision": item.attrib.get("Revision"),
        "raw_xml": ET.tostring(item, encoding="unicode"),
    }


def fetch_feed(feed_url: str = FEED_URL, limit: int | None = None) -> list[dict]:
    """Fetch and parse the MSRC RSS feed, return list of serialized items."""
    logger.info("Fetching feed: %s", feed_url)
    response = requests.get(feed_url, headers=REQUEST_HEADERS, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    root = ET.fromstring(response.content)
    channel = root.find("channel")
    if channel is None:
        items = root.findall(".//item")
        serialized = [_serialize_item(item) for item in items[: limit or None]]
        logger.info("Fetched %d items", len(serialized))
        return serialized

    serialized: list[dict] = []
    for item in _iter_items(channel):
        serialized.append(_serialize_item(item))
        if limit and len(serialized) >= limit:
            break
    logger.info("Fetched %d items", len(serialized))
    return serialized


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(item: dict) -> dict:
    """Convert a serialized RSS item to a SecLens bulletin dict."""
    fetched_at = now_utc_iso()
    published_at = parse_first(
        [(item.get("pub_date"), "item.pubDate")],
        default_tz="UTC",
    )

    # Truncate title to match database field limit (VARCHAR(500))
    title = (item.get("title") or "")[:500]
    description = item.get("description")
    origin_url = item.get("link")
    categories = item.get("categories") or []
    revision = item.get("revision")
    guid = item.get("guid")

    external_id = guid or origin_url or None
    if external_id and revision:
        external_id = f"{external_id}#rev-{revision}"

    labels = [category for category in categories if category]
    topics = ["official_bulletin"]
    if any(isinstance(category, str) and category.upper() == "CVE" for category in categories):
        topics.append("cve")

    extra: dict[str, object] = {
        "revision": revision,
        "categories": categories,
        "guid": guid,
        "guid_attributes": item.get("guid_attributes") or {},
    }

    raw_payload = {
        key: value
        for key, value in item.items()
        if key != "raw_xml"
    }
    if item.get("raw_xml"):
        raw_payload["raw_xml"] = item["raw_xml"]

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
            "title": title,
            "summary": description,
            "body_text": description,
            "published_at": published_at,
            "language": "en",
        },
        "severity": None,
        "fetched_at": fetched_at,
        "labels": labels,
        "topics": topics,
        "extra": extra,
        "raw": raw_payload,
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
    logger.info("Server response: accepted=%s, duplicates=%s", result.get("accepted"), result.get("duplicates"))
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

    items = fetch_feed()
    if not items:
        logger.info("No feed items fetched")
        return

    newest_cursor = str(
        items[0].get("guid")
        or items[0].get("link")
        or items[0].get("title")
        or ""
    )
    cursor = load_cursor()
    if cursor:
        fresh_items: list[dict] = []
        for item in items:
            item_cursor = str(item.get("guid") or item.get("link") or item.get("title") or "")
            if item_cursor == cursor:
                break
            fresh_items.append(item)
        logger.info("Cursor loaded: %s, %d new candidate items", cursor, len(fresh_items))
        items = fresh_items
    else:
        logger.info("No cursor found, treating current feed as initial batch")

    if not items:
        logger.info("No new items since cursor, skip push")
        return

    bulletins = [normalize(item) for item in items]

    if not bulletins:
        logger.info("No items to push")
        return

    result = push_to_seclens(bulletins)
    if newest_cursor:
        save_cursor(newest_cursor)
    logger.info(
        "Done: %d fetched, %d accepted, %d duplicates",
        len(bulletins),
        result.get("accepted", 0),
        result.get("duplicates", 0),
    )


if __name__ == "__main__":
    main()
