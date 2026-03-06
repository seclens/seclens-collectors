"""The Hacker News RSS collector.

Fetches cybersecurity headlines from The Hacker News RSS feed and pushes
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
from email.utils import parsedate_to_datetime

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")
FEED_URL = os.environ.get(
    "THN_FEED_URL", "https://feeds.feedburner.com/TheHackersNews"
)
SOURCE_SLUG = "the_hacker_news"
USER_AGENT = "SeclensCollector/2.0 (the_hacker_news)"
REQUEST_TIMEOUT = 30

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


def fetch_feed(feed_url: str = FEED_URL) -> list[ET.Element]:
    """Fetch and parse the RSS feed, return list of <item> elements."""
    logger.info("Fetching feed: %s", feed_url)
    resp = requests.get(
        feed_url,
        timeout=REQUEST_TIMEOUT,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/rss+xml, application/xml;q=0.9, */*;q=0.8",
        },
    )
    resp.raise_for_status()

    root = ET.fromstring(resp.content)
    channel = root.find("channel")
    items = channel.findall("item") if channel is not None else root.findall(".//item")
    logger.info("Fetched %d items", len(items))
    return items


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def _trim(text: str | None) -> str | None:
    """Strip whitespace, return None for empty strings."""
    if not text:
        return None
    cleaned = text.strip()
    return cleaned or None


def _find_content_encoded(node: ET.Element) -> str | None:
    """Find <content:encoded> element regardless of namespace prefix."""
    for child in node:
        if child.tag.lower().endswith("encoded"):
            return _trim(child.text)
    return None


def _parse_pub_date(raw: str | None) -> str | None:
    """Parse RSS pubDate to ISO 8601 string. Returns None on failure."""
    if not raw or not raw.strip():
        return None
    try:
        dt = parsedate_to_datetime(raw.strip())
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return None


def normalize(item: ET.Element) -> dict:
    """Convert an RSS <item> element to SecLens bulletin dict."""
    title = _trim(item.findtext("title")) or ""
    link = _trim(item.findtext("link"))
    description = _trim(item.findtext("description"))
    content_encoded = _find_content_encoded(item)
    pub_date_raw = _trim(item.findtext("pubDate"))
    guid_node = item.find("guid")
    guid = _trim(guid_node.text) if guid_node is not None else None

    categories = [
        _trim(cat.text)
        for cat in item.findall("category")
        if _trim(cat.text)
    ]

    external_id = guid or link
    published_at = _parse_pub_date(pub_date_raw)
    body_text = content_encoded or description

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": external_id,
            "origin_url": link,
        },
        "content": {
            "title": title,
            "summary": description,
            "body_text": body_text,
            "published_at": published_at,
            "language": "en",
        },
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "labels": [f"category:{c.lower()}" for c in categories],
        "topics": ["security-news"],
        "extra": {
            "categories": categories,
            "guid": guid,
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
