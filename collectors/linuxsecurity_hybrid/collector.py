"""LinuxSecurity.com hybrid RSS collector.

Fetches combined advisories, features, and news from LinuxSecurity.com
hybrid RSS feed and pushes them to a SecLens server. Fully standalone -
no SecLens app dependencies.

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
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
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
DEFAULT_FEED_URL = os.environ.get(
    "LINUXSECURITY_FEED_URL",
    "https://linuxsecurity.com/linuxsecurity_hybrid.xml",
)
SOURCE_SLUG = "linuxsecurity_hybrid"
USER_AGENT = "SeclensCollector/2.0 (linuxsecurity_hybrid)"
REQUEST_TIMEOUT = 30
STATE_FILE_NAME = ".cursor"
REQUEST_HEADERS = {
    "Accept": "application/rss+xml, application/xml;q=0.9, */*;q=0.8",
    "User-Agent": USER_AGENT,
}
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


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
# Helpers
# ---------------------------------------------------------------------------


@dataclass
class FetchParams:
    feed_url: str = DEFAULT_FEED_URL
    limit: int | None = None


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


class LinuxSecurityCollector:
    """Fetch and normalize LinuxSecurity.com RSS entries."""

    def __init__(self, session: requests.Session | None = None) -> None:
        self.session = session or requests.Session()
        self.session.headers.update(REQUEST_HEADERS)

    def fetch(self, params: FetchParams) -> Sequence[dict]:
        response = self.session.get(params.feed_url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        root = ET.fromstring(response.content)
        channel = root.find("channel")
        items = channel.findall("item") if channel is not None else root.findall(".//item")

        serialized: list[dict] = []
        for item in items:
            serialized.append(self._serialize_item(item))
            if params.limit and len(serialized) >= params.limit:
                break
        return serialized

    def _serialize_item(self, item: ET.Element) -> dict:
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

    # ------------------------------------------------------------------
    # Normalize
    # ------------------------------------------------------------------

    def normalize(self, item: dict) -> dict:
        """Convert a serialized RSS item to a SecLens bulletin dict."""
        published_at = parse_first(
            [(item.get("pub_date"), "item.pubDate")],
            default_tz="UTC",
        )

        origin_url = item.get("link")
        description = item.get("description")
        body_text = item.get("content_encoded") or description
        external_id = item.get("guid") or origin_url

        categories = item.get("categories") or []
        labels = [f"category:{category.lower()}" for category in categories]

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
                "title": item.get("title") or (origin_url or ""),
                "summary": description,
                "body_text": body_text,
                "published_at": published_at,
                "language": "en",
            },
            "severity": None,
            "fetched_at": now_utc_iso(),
            "labels": labels,
            "topics": ["security-news"],
            "extra": {
                "categories": categories,
                "guid": item.get("guid"),
                "guid_attributes": item.get("guid_attributes") or {},
            },
            "raw": raw_payload,
        }

    def collect(self, params: FetchParams | None = None) -> list[dict]:
        params = params or FetchParams()
        entries = self.fetch(params)
        return [self.normalize(item) for item in entries]


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

    collector = LinuxSecurityCollector()
    entries = collector.fetch(FetchParams())
    latest_cursor = str(entries[0].get("guid") or entries[0].get("link")) if entries else None
    previous_cursor = load_cursor()
    if previous_cursor:
        filtered: list[dict] = []
        for item in entries:
            cursor_value = str(item.get("guid") or item.get("link") or "")
            if cursor_value == previous_cursor:
                break
            filtered.append(item)
        entries = filtered
        logger.info(
            "Cursor check: previous=%s, pending=%d",
            previous_cursor,
            len(entries),
        )

    bulletins = [collector.normalize(item) for item in entries]
    logger.info("Fetched %d bulletins", len(bulletins))

    if not bulletins:
        logger.info("No items to push")
        return

    result = push_to_seclens(bulletins)
    if latest_cursor:
        save_cursor(latest_cursor)
    logger.info(
        "Done: fetched=%d accepted=%s duplicates=%s",
        len(bulletins),
        result.get("accepted", 0),
        result.get("duplicates", 0),
    )


if __name__ == "__main__":
    main()
