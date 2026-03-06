"""Amazon Linux 1 ALAS RSS collector.

Fetches security bulletins from Amazon Linux 1 ALAS RSS feed and pushes
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
import re
import sys
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Sequence

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.time_helpers import parse_first, now_utc_iso

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")
FEED_URL = os.environ.get(
    "ALAS_AL1_FEED_URL", "https://alas.aws.amazon.com/alas.rss"
)
SOURCE_SLUG = "amazon_linux_al1"
USER_AGENT = "SeclensCollector/2.0 (amazon_linux_al1)"
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

TITLE_PATTERN = re.compile(r"^(?P<bulletin>[A-Z0-9-]+)\s*(?:\((?P<severity>[^)]+)\))?\s*:\s*(?P<component>.+?)\s*$")
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


@dataclass
class FetchParams:
    feed_url: str = FEED_URL
    limit: int | None = 10


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clean_text(value: str | None) -> str | None:
    if not value:
        return None
    normalised = unicodedata.normalize("NFKC", value)
    cleaned = " ".join(normalised.split())
    return cleaned or None


def _parse_pubdate(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _extract_cves(text: str | None) -> list[str]:
    if not text:
        return []
    return sorted({match.upper() for match in CVE_PATTERN.findall(text)})


def _parse_title(title: str | None) -> tuple[str | None, str | None, str | None]:
    if not title:
        return None, None, None
    match = TITLE_PATTERN.match(title.strip())
    if not match:
        return title.strip(), None, None
    return match.group("bulletin"), match.group("severity"), match.group("component")


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


class AmazonLinux1Collector:
    """Fetch and normalise Amazon Linux 1 security bulletins."""

    def __init__(self, session: requests.Session | None = None) -> None:
        self.session = session or requests.Session()
        self.session.headers.update(REQUEST_HEADERS)

    def fetch(self, params: FetchParams) -> Sequence[dict]:
        response = self.session.get(params.feed_url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        root = ET.fromstring(response.content)
        items: list[dict] = []
        for item in root.findall("./channel/item"):
            parsed = self._parse_item(item)
            if not parsed:
                continue
            items.append(parsed)
            if params.limit and len(items) >= params.limit:
                break
        logger.info("Fetched %d items from feed", len(items))
        return items

    def _parse_item(self, item: ET.Element) -> dict | None:
        title_raw = item.findtext("title")
        description_raw = item.findtext("description")
        link = _clean_text(item.findtext("link"))
        guid = _clean_text(item.findtext("guid"))
        pub_date = _parse_pubdate(item.findtext("pubDate"))

        if not title_raw and not link:
            return None

        title_clean = _clean_text(title_raw) or link or guid
        description_clean = _clean_text(description_raw)
        bulletin_id, severity, component = _parse_title(title_clean)
        cves = _extract_cves(description_raw or "")

        return {
            "title": title_clean,
            "link": link,
            "guid": guid,
            "pub_date": pub_date,
            "description": description_clean,
            "bulletin_id": bulletin_id or title_clean,
            "severity": severity,
            "component": component,
            "cves": cves,
        }


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(entry: dict) -> dict:
    """Convert a parsed feed entry to SecLens bulletin dict."""
    fetched_at = now_utc_iso()

    candidates: list[tuple[object, str]] = []
    if entry.get("pub_date"):
        candidates.append((entry["pub_date"], "item.pubDate"))

    published_at = parse_first(candidates, default_tz="UTC")

    origin_url = entry.get("link") or entry.get("guid")
    external_id = entry.get("bulletin_id") or origin_url

    summary = entry.get("description")
    body_text = entry.get("description")

    labels = ["vendor:aws", "distribution:al1"]
    if entry.get("severity"):
        labels.append(f"severity:{entry['severity'].strip().lower()}")
    if entry.get("component"):
        labels.append(f"component:{entry['component'].strip().lower()}")
    for cve in entry.get("cves") or []:
        labels.append(f"cve:{cve.lower()}")

    labels = [_clean_text(label) for label in labels if _clean_text(label)]

    topics = ["vendor-update", "official_advisory"]

    extra: dict[str, object] = {
        "bulletin_id": entry.get("bulletin_id"),
        "severity": entry.get("severity"),
        "component": entry.get("component"),
        "cves": entry.get("cves"),
    }

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": str(external_id),
            "origin_url": origin_url,
        },
        "content": {
            "title": entry.get("title") or external_id,
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

    collector = AmazonLinux1Collector()
    entries = collector.fetch(FetchParams(feed_url=FEED_URL))
    bulletins = []
    for entry in entries:
        try:
            bulletins.append(normalize(entry))
        except Exception as exc:
            logger.exception("Failed to normalise Amazon Linux 1 entry: %s", entry, exc_info=exc)

    if not bulletins:
        logger.info("No items to push")
        return

    result = push_to_seclens(bulletins)
    print(f"Done: {len(bulletins)} fetched, {result.get('accepted', 0)} accepted, {result.get('duplicates', 0)} duplicates")


if __name__ == "__main__":
    main()
