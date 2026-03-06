"""VIPRead RSS collector - standalone version.

Fetches security knowledge articles from the VIPRead RSS feed and pushes
them to a SecLens server.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 4 hours (14400s)
"""
from __future__ import annotations

import html
import logging
import os
import re
import sys
import xml.etree.ElementTree as ET

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
FEED_URL = os.environ.get("VIPREAD_FEED_URL", "https://vipread.com/rss")

SOURCE_SLUG = "vipread"
USER_AGENT = "SeclensCollector/2.0 (vipread)"
REQUEST_TIMEOUT = 30
REQUEST_HEADERS = {
    "Accept": "application/rss+xml, application/xml;q=0.9, */*;q=0.8",
    "User-Agent": USER_AGENT,
}

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


def _clean_html(value: str | None) -> str | None:
    """Clean HTML tags and normalize entities."""
    if value is None:
        return None
    cleaned = html.unescape(value)
    cleaned = re.sub(r'<[^>]+>', ' ', cleaned)
    cleaned = re.sub(r'\s+', ' ', cleaned)
    return cleaned.strip() or None


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


def fetch_feed(feed_url: str = FEED_URL, limit: int | None = None) -> list[dict]:
    """Fetch and parse the VIPRead RSS feed."""
    logger.info("Fetching feed: %s", feed_url)
    session = requests.Session()
    session.headers.update(REQUEST_HEADERS)
    response = session.get(feed_url, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    root = ET.fromstring(response.content)
    channel = root.find("channel")
    items = channel.findall("item") if channel is not None else root.findall(".//item")

    serialized: list[dict] = []
    for item in items:
        serialized.append(
            {
                "title": _trim(item.findtext("title")) or "",
                "link": _trim(item.findtext("link")),
                "description": _trim(item.findtext("description")),
                "guid": _trim(item.findtext("guid")),
                "pub_date": _trim(item.findtext("pubDate")),
                "raw_xml": ET.tostring(item, encoding="unicode"),
            }
        )
        if limit and len(serialized) >= limit:
            break

    logger.info("Fetched %d items from feed", len(serialized))
    return serialized


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(item: dict) -> dict:
    """Convert a feed entry dict to a SecLens bulletin dict."""
    published_at = parse_first(
        [(item.get("pub_date"), "item.pubDate")],
        default_tz="Asia/Shanghai",
    )

    origin_url = item.get("link")
    title = item.get("title") or (origin_url or "")

    raw_description = item.get("description")
    description = _clean_html(raw_description)

    external_id = item.get("guid") or origin_url or item.get("link")

    extra: dict = {}

    raw_payload = {k: v for k, v in item.items() if k != "raw_xml"}
    if item.get("raw_xml"):
        raw_payload["raw_xml"] = item["raw_xml"]

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": external_id,
            "origin_url": origin_url,
        },
        "content": {
            "title": title,
            "summary": description,
            "body_text": description,
            "published_at": published_at,
            "language": "zh",
        },
        "severity": None,
        "fetched_at": now_utc_iso(),
        "labels": [],
        "topics": ["security-knowledge", "security-news"],
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

    entries = fetch_feed()
    bulletins = [normalize(entry) for entry in entries]

    if not bulletins:
        logger.info("No items to push")
        return

    result = push_to_seclens(bulletins)
    print(
        f"Done: {len(bulletins)} fetched, "
        f"{result.get('accepted', 0)} accepted, "
        f"{result.get('duplicates', 0)} duplicates"
    )


if __name__ == "__main__":
    main()
