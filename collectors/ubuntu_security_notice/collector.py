"""Ubuntu Security Notices collector.

Fetches Ubuntu USN advisories via RSS and JSON endpoints and pushes them
to a SecLens server. Fully standalone - no SecLens app dependencies.

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
from dataclasses import dataclass
from datetime import datetime, timezone
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
    "UBUNTU_FEED_URL", "https://ubuntu.com/security/notices/rss.xml"
)
SOURCE_SLUG = "ubuntu_security_notice"
USER_AGENT = "SeclensCollector/2.0 (ubuntu_security_notice)"
REQUEST_TIMEOUT = 30
DEFAULT_LIMIT = 20
STATE_FILE_NAME = ".cursor"
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug("ubuntu_security_notice")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)
UTC = timezone.utc  # noqa: UP017


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class FeedEntry:
    notice_id: str
    title: str
    link: str
    summary: str | None
    published_at: str | None
    guid: str | None
    fetched_at: str
    raw_pub_date: str | None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    return " ".join(value.split()).strip() or None


def _extract_notice_id(link: str) -> str:
    segment = link.rstrip("/").split("/")[-1]
    return segment.upper()


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
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _save_cursor(value: datetime) -> None:
    value = value.astimezone(UTC)
    _cursor_path().write_text(value.isoformat(), encoding="utf-8")


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


def fetch_feed(feed_url: str = FEED_URL) -> list[FeedEntry]:
    """Fetch and parse the Ubuntu security notices RSS feed."""
    logger.info("Fetching feed: %s", feed_url)
    resp = requests.get(
        feed_url,
        timeout=REQUEST_TIMEOUT,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/rss+xml, application/json, text/xml;q=0.9, */*;q=0.8",
        },
    )
    resp.raise_for_status()
    text = resp.text.lstrip()
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("Failed to parse Ubuntu RSS feed") from exc

    entries: list[FeedEntry] = []
    for item in root.findall("./channel/item"):
        link = (item.findtext("link") or "").strip()
        if not link:
            continue
        notice_id = _extract_notice_id(link)
        title = _clean_text(item.findtext("title")) or notice_id
        summary = _clean_text(item.findtext("description"))
        fetched_at = now_utc_iso()
        raw_pub_date = item.findtext("pubDate")
        published_at = parse_first(
            [(raw_pub_date, "item.pubDate")],
            default_tz="UTC",
        )
        guid = _clean_text(item.findtext("guid"))
        entries.append(
            FeedEntry(
                notice_id=notice_id,
                title=title,
                link=link,
                summary=summary,
                published_at=published_at,
                guid=guid,
                fetched_at=fetched_at,
                raw_pub_date=raw_pub_date.strip() if isinstance(raw_pub_date, str) else None,
            )
        )
    logger.info("Fetched %d items from RSS", len(entries))
    return entries


def fetch_detail(link: str) -> dict:
    """Fetch the JSON detail for a specific notice."""
    detail_url = f"{link}.json" if not link.endswith(".json") else link
    resp = requests.get(
        detail_url,
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    )
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(entry: FeedEntry, detail: dict) -> dict:
    """Convert a feed entry + detail into a SecLens bulletin dict."""
    summary = _clean_text(detail.get("summary")) or entry.summary
    body_text = detail.get("description") or summary
    published = detail.get("published")
    published_at = parse_first(
        [
            (published, "detail.published"),
            (entry.published_at, "entry.published_at"),
            (entry.raw_pub_date, "feed.pubDate"),
        ],
        default_tz="UTC",
    )

    notice_type = detail.get("type")
    labels: list[str] = []
    if notice_type:
        labels.append(str(notice_type))
    releases = detail.get("releases") or []
    if isinstance(releases, list):
        for release in releases:
            codename = release.get("codename") if isinstance(release, dict) else None
            if codename:
                labels.append(f"release:{codename}")

    cve_ids: list[str] = []
    if isinstance(detail.get("cves_ids"), list):
        cve_ids = [str(cve) for cve in detail["cves_ids"] if cve]
    elif isinstance(detail.get("cves"), list):
        for item in detail["cves"]:
            if isinstance(item, dict) and item.get("id"):
                cve_ids.append(str(item["id"]))

    topics = ["official_bulletin"]
    if cve_ids:
        topics.append("cve")

    extra: dict[str, object] = {}
    for key in ("instructions", "references", "release_packages", "releases"):
        value = detail.get(key)
        if value:
            extra[key] = value
    if cve_ids:
        extra["cve_ids"] = cve_ids
    if entry.guid:
        extra["guid"] = entry.guid
    if entry.raw_pub_date:
        extra.setdefault("raw_pub_date", entry.raw_pub_date)

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": entry.notice_id,
            "origin_url": entry.link,
            "manifest": MANIFEST,
            "manifest_hash": MANIFEST_HASH,
            "manifest_version": MANIFEST_VERSION,
        },
        "content": {
            "title": entry.title,
            "summary": summary,
            "body_text": body_text,
            "published_at": published_at,
            "language": "en",
        },
        "severity": None,
        "fetched_at": entry.fetched_at,
        "labels": labels,
        "topics": topics,
        "extra": extra or None,
        "raw": {"detail": detail},
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
            detail = fetch_detail(entry.link)
            bulletin = normalize(entry, detail)
            bulletins.append(bulletin)
            if entry.published_at:
                entry_dt = datetime.fromisoformat(entry.published_at)
                if latest_dt is None or entry_dt > latest_dt:
                    latest_dt = entry_dt
        except Exception as exc:
            logger.exception("Failed to process entry %s: %s", entry.notice_id, exc)

    if not bulletins:
        logger.info("No items to push")
        return

    result = push_to_seclens(bulletins)

    if latest_dt and bulletins:
        _save_cursor(latest_dt)

    logger.info(
        "Done: %d fetched, %d accepted, %d duplicates",
        len(bulletins),
        result.get("accepted", 0),
        result.get("duplicates", 0),
    )


if __name__ == "__main__":
    main()
