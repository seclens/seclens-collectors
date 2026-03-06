"""Sihou (4hou.com) security news RSS collector.

Fetches security news from the Sihou (4hou.com) RSS feed and pushes
them to a SecLens server. Fully standalone - no SecLens app dependencies.

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
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.time_helpers import parse_first, now_utc_iso

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")

SOURCE_SLUG = "sihou_news"
DEFAULT_FEED_URL = os.environ.get("SIHOU_FEED_URL", "https://www.4hou.com/feed")
USER_AGENT = "SeclensCollector/2.0 (sihou_news)"
REQUEST_HEADERS = {
    "Accept": "application/rss+xml, application/xml;q=0.9, */*;q=0.8",
    "User-Agent": USER_AGENT,
}
REQUEST_TIMEOUT = 30

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _trim(text: str | None) -> str | None:
    if not text:
        return None
    cleaned = text.strip()
    return cleaned or None


def _find_encoded(node: ET.Element) -> str | None:
    for child in node:
        if child.tag.lower().endswith("encoded"):
            return _trim(child.text)
    return None


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


def fetch_feed(feed_url: str = DEFAULT_FEED_URL) -> list[dict]:
    """Fetch and parse the RSS feed, return list of serialized items."""
    logger.info("Fetching feed: %s", feed_url)
    resp = requests.get(
        feed_url,
        timeout=REQUEST_TIMEOUT,
        headers=REQUEST_HEADERS,
    )
    resp.raise_for_status()

    root = ET.fromstring(resp.content)
    channel = root.find("channel")
    items = channel.findall("item") if channel is not None else root.findall(".//item")
    logger.info("Fetched %d items", len(items))

    serialized: list[dict] = []
    for item in items:
        serialized.append(_serialize_item(item))
    return serialized


def _serialize_item(item: ET.Element) -> dict:
    guid_node = item.find("guid")
    categories = [
        _trim(cat.text)
        for cat in item.findall("category")
        if _trim(cat.text)
    ]
    description = _trim(item.findtext("description"))
    encoded = _find_encoded(item)
    return {
        "title": _trim(item.findtext("title")) or "",
        "link": _trim(item.findtext("link")),
        "description": description,
        "content_encoded": encoded,
        "guid": _trim(guid_node.text if guid_node is not None else None),
        "guid_attributes": dict(guid_node.attrib) if guid_node is not None else {},
        "pub_date": _trim(item.findtext("pubDate")),
        "categories": categories,
        "raw_xml": ET.tostring(item, encoding="unicode"),
    }


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(item: dict) -> dict:
    """Convert an RSS item dict to a SecLens bulletin dict."""
    fetched_at = now_utc_iso()
    published_at = parse_first(
        [(item.get("pub_date"), "item.pubDate")],
        default_tz="Asia/Shanghai",
    )
    origin_url = item.get("link")
    description = item.get("description")
    body_text = item.get("content_encoded") or description

    external_id = item.get("guid") or origin_url

    categories = item.get("categories") or []
    labels = [f"category:{category.lower()}" for category in categories]
    topics = ["security-news"]

    extra: dict[str, object] = {
        "categories": categories,
        "guid": item.get("guid"),
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
        },
        "content": {
            "title": item.get("title") or (origin_url or ""),
            "summary": description,
            "body_text": body_text,
            "published_at": published_at,
            "language": "zh",
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
    bulletins = [normalize(item) for item in items]

    if not bulletins:
        logger.info("No items to push")
        return

    result = push_to_seclens(bulletins)
    print(f"Done: {len(bulletins)} fetched, {result.get('accepted', 0)} accepted, {result.get('duplicates', 0)} duplicates")


if __name__ == "__main__":
    main()
