"""AWS Security Bulletins RSS collector.

Fetches security bulletins from the official AWS Security Bulletins RSS feed
and pushes them to a SecLens server. Fully standalone - no SecLens app dependencies.

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
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Iterable, Sequence
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup, NavigableString, Tag

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.time_helpers import parse_first, now_utc_iso

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")
FEED_URL = os.environ.get(
    "AWS_FEED_URL", "https://aws.amazon.com/security/security-bulletins/rss/feed/"
)
SOURCE_SLUG = "aws_security_bulletins"
USER_AGENT = "SeclensCollector/2.0 (aws_security_bulletins)"
REQUEST_TIMEOUT = 30

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)

REQUEST_HEADERS = {
    "Accept": "application/rss+xml,application/xml;q=0.9,text/xml;q=0.8,*/*;q=0.7",
    "User-Agent": USER_AGENT,
}


@dataclass
class FetchParams:
    feed_url: str = FEED_URL
    limit: int | None = 20


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clean_text(value: str | None) -> str | None:
    if not value:
        return None
    normalised = unicodedata.normalize("NFKC", value)
    collapsed = " ".join(normalised.split())
    return collapsed or None


def _slugify(value: str | None) -> str:
    if not value:
        return "value"
    normalised = unicodedata.normalize("NFKD", value)
    chars: list[str] = []
    for char in normalised:
        if char.isalnum():
            chars.append(char.lower())
        elif char in {" ", "-", "_", "/", ":", "."}:
            chars.append("-")
    slug = "".join(chars).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or "value"


def _parse_pub_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _harvest_label_values(paragraph: Tag) -> dict[str, str]:
    result: dict[str, str] = {}
    current_label: str | None = None
    buffer: list[str] = []

    def flush() -> None:
        nonlocal current_label, buffer
        if current_label and buffer:
            value = _clean_text(" ".join(buffer))
            if value:
                result[current_label] = value
        current_label = None
        buffer = []

    for child in paragraph.children:
        if isinstance(child, Tag) and child.name == "b":
            flush()
            label = _clean_text(child.get_text(" ", strip=True))
            if label:
                current_label = label.rstrip(":")
        elif isinstance(child, Tag) and child.name == "br":
            flush()
        else:
            text: str | None = None
            if isinstance(child, NavigableString):
                text = _clean_text(str(child))
            elif isinstance(child, Tag):
                text = _clean_text(child.get_text(" ", strip=True))
            if text:
                buffer.append(text)

    flush()
    return result


def _parse_description(description_html: str | None) -> tuple[dict[str, str], list[str]]:
    if not description_html:
        return {}, []
    soup = BeautifulSoup(description_html, "html.parser")
    details: dict[str, str] = {}
    paragraphs: list[str] = []

    for paragraph in soup.find_all("p"):
        harvested = _harvest_label_values(paragraph)
        if harvested:
            for key, value in harvested.items():
                details[key] = value
        paragraph_text = _clean_text(paragraph.get_text(" ", strip=True))
        if paragraph_text:
            paragraphs.append(paragraph_text)
    return details, paragraphs


def _first_meaningful_paragraph(paragraphs: Iterable[str]) -> str | None:
    for text in paragraphs:
        lowered = text.lower()
        if lowered.startswith("bulletin id:"):
            continue
        if lowered.startswith("scope:"):
            continue
        if lowered.startswith("content type:"):
            continue
        if lowered.startswith("publication date:"):
            continue
        if lowered.startswith("description:"):
            continue
        if lowered.startswith("affected"):
            continue
        return text
    return next(iter(paragraphs), None) if hasattr(paragraphs, "__iter__") else None


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


def fetch_feed(feed_url: str = FEED_URL, limit: int | None = 20) -> list[dict]:
    """Fetch and parse the AWS Security Bulletins RSS feed."""
    logger.info("Fetching feed: %s", feed_url)
    response = requests.get(feed_url, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS)
    response.raise_for_status()
    root = ET.fromstring(response.content)
    entries: list[dict] = []
    for item in root.findall("./channel/item"):
        parsed = _parse_item(item)
        if not parsed:
            continue
        entries.append(parsed)
        if limit and len(entries) >= limit:
            break
    logger.info("Fetched %d items", len(entries))
    return entries


def _parse_item(item: ET.Element) -> dict | None:
    title = _clean_text(item.findtext("title"))
    link = _clean_text(item.findtext("link"))
    guid = _clean_text(item.findtext("guid"))
    description = item.findtext("description")
    pub_date = _parse_pub_date(item.findtext("pubDate"))
    author = _clean_text(item.findtext("author"))

    if not title and not link:
        return None

    details, paragraphs = _parse_description(description)

    return {
        "title": title,
        "link": link,
        "guid": guid,
        "pub_date": pub_date,
        "author": author,
        "details": details,
        "paragraphs": paragraphs,
        "description_html": description,
    }


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(entry: dict) -> dict:
    """Convert a parsed RSS entry to a SecLens bulletin dict."""
    fetched_at = now_utc_iso()

    candidates: list[tuple[object, str]] = []
    if entry.get("pub_date"):
        candidates.append((entry["pub_date"], "item.pubDate"))
    publication_detail = entry.get("details", {}).get("Publication Date")
    if publication_detail:
        candidates.append((publication_detail, "item.details.Publication Date"))

    published_at = parse_first(candidates, default_tz="UTC")

    link = entry.get("link")
    external_id = None
    if link:
        parsed = urlparse(link)
        external_id = parsed.path.rstrip("/").rsplit("/", 1)[-1]
    if not external_id:
        external_id = entry.get("guid") or _slugify(entry.get("title"))

    paragraphs: list[str] = entry.get("paragraphs") or []
    summary = _first_meaningful_paragraph(paragraphs)
    body_text = "\n\n".join(paragraphs) if paragraphs else None

    details = entry.get("details") or {}

    labels = ["vendor:aws"]
    bulletin_id = details.get("Bulletin ID")
    if bulletin_id:
        labels.append(f"bulletin:{_slugify(bulletin_id)}")
    content_type = details.get("Content Type")
    if content_type:
        labels.append(f"severity:{_slugify(content_type)}")

    labels = [label for label in labels if label]

    topics = ["official_advisory", "vulnerability_alert"]

    extra: dict[str, object] = {
        "bulletin_id": bulletin_id,
        "scope": details.get("Scope"),
        "content_type": content_type,
        "publication_detail": publication_detail,
        "author": entry.get("author"),
        "details": details,
    }

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": str(external_id),
            "origin_url": link,
        },
        "content": {
            "title": entry.get("title") or (link or str(external_id)),
            "summary": summary,
            "body_text": body_text,
            "published_at": published_at,
            "language": "en",
        },
        "severity": None,
        "fetched_at": fetched_at,
        "labels": labels,
        "topics": topics,
        "extra": {k: v for k, v in extra.items() if v},
        "raw": entry,
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
