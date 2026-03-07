"""Oracle Security Alert collector.

Fetches Oracle Security Alert RSS feed entries and pushes them to a SecLens
server. Fully standalone - no SecLens app dependencies.

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
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

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
    "ORACLE_FEED_URL",
    "https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml",
)
SOURCE_SLUG = "oracle_security_alert"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
ARTICLE_ACCEPT = "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"
STATE_FILE_NAME = ".cursor"
REQUEST_TIMEOUT = 30
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)
UTC = timezone.utc  # noqa: UP017


# ---------------------------------------------------------------------------
# Cursor helpers
# ---------------------------------------------------------------------------


def _state_path() -> Path:
    return Path(__file__).resolve().with_name(STATE_FILE_NAME)


def load_cursor() -> datetime | None:
    try:
        raw = _state_path().read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        logger.warning("Invalid cursor value '%s'", raw)
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def save_cursor(value: datetime) -> None:
    value = value.astimezone(UTC)
    _state_path().write_text(value.isoformat(), encoding="utf-8")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_valid_url(value: str | None) -> bool:
    if not value:
        return False
    parsed = urlparse(value.strip())
    return bool(parsed.scheme and parsed.netloc)


def _derive_external_id(guid: str | None, link: str | None, title: str | None) -> str | None:
    candidates: list[str] = []
    if guid:
        candidates.append(guid)
    if link and _is_valid_url(link):
        parsed = urlparse(link)
        slug = Path(parsed.path).stem
        if slug:
            candidates.append(slug)
    if link:
        candidates.append(link)
    if title:
        candidates.append(title)
    for candidate in candidates:
        cleaned = candidate.strip()
        if cleaned:
            return cleaned
    return None


def _is_noise_text(value: str) -> bool:
    normalized = value.strip().lower()
    return normalized in {"skip to content", "skip to main content"}


def _collect_paragraphs(root) -> list[str]:
    if root is None:
        return []
    paragraphs: list[str] = []
    seen: set[str] = set()
    for element in root.find_all(["p", "li"]):
        text = " ".join(element.stripped_strings)
        if not text:
            continue
        if _is_noise_text(text):
            continue
        if text in seen:
            continue
        seen.add(text)
        paragraphs.append(text)
    return paragraphs


def _strip_noise_lines(text: str) -> str:
    if not text:
        return text
    lines = []
    for line in text.splitlines():
        cleaned = line.strip()
        if not cleaned:
            continue
        if _is_noise_text(cleaned):
            continue
        lines.append(cleaned)
    return "\n\n".join(lines)


def _remove_tracked_sections(soup: BeautifulSoup, *, marker: str) -> None:
    for element in soup.select(f'[data-trackas="{marker}"]'):
        element.decompose()


def _extract_text(html: str) -> str | None:
    soup = BeautifulSoup(html, "html.parser")
    _remove_tracked_sections(soup, marker="header")
    _remove_tracked_sections(soup, marker="footer")
    paragraphs = _collect_paragraphs(
        soup.select_one("article")
        or soup.select_one(".content")
        or soup.select_one("#content")
        or soup.select_one(".main-content")
        or soup.body
        or soup
    )
    if not paragraphs:
        fallback = soup.get_text(separator="\n\n", strip=True)
        text = _strip_noise_lines(fallback)
        return text or None
    text = "\n\n".join(paragraphs).strip()
    return text or None


def _clean_summary(value: str | None) -> str | None:
    if not value:
        return None
    soup = BeautifulSoup(value, "html.parser")
    text = soup.get_text(" ", strip=True)
    return text or None


def _generate_summary(body: str, *, limit: int) -> str | None:
    text = body.strip()
    if not text:
        return None
    if len(text) <= limit:
        return text
    truncated = text[:limit].rstrip()
    if not truncated:
        return text[:limit]
    return f"{truncated}..."


def _fetch_article_body(url: str | None) -> str | None:
    if not _is_valid_url(url):
        return None
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT, "Accept": ARTICLE_ACCEPT},
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        logger.debug("Failed to fetch article %s: %s", url, exc)
        return None
    return _extract_text(response.text)


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


@dataclass
class FeedEntry:
    guid: str
    title: str
    link: str
    description: str | None
    published_at: str | None  # ISO 8601 string
    fetched_at: str  # ISO 8601 string
    raw_pub_date: str | None


def fetch_feed(feed_url: str = FEED_URL) -> list[FeedEntry]:
    """Fetch and parse the Oracle Security Alert RSS feed."""
    logger.info("Fetching feed: %s", feed_url)
    response = requests.get(
        feed_url,
        timeout=REQUEST_TIMEOUT,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/rss+xml, application/xml;q=0.9, */*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    response.raise_for_status()
    try:
        root = ET.fromstring(response.text)
    except ET.ParseError as exc:
        raise ValueError("Failed to parse Oracle Security Alert RSS feed") from exc

    items: list[FeedEntry] = []
    for item in root.findall("./channel/item"):
        link = (item.findtext("link") or "").strip()
        title = (item.findtext("title") or link).strip()
        description = item.findtext("description") or None
        guid = (item.findtext("guid") or link or title).strip()
        fetched_at = now_utc_iso()
        raw_pub_date = item.findtext("pubDate")
        published_at = parse_first(
            [(raw_pub_date, "item.pubDate")],
            default_tz="UTC",
        )
        if not link:
            continue
        items.append(
            FeedEntry(
                guid=guid or link,
                title=title or link,
                link=link,
                description=description.strip() if description else None,
                published_at=published_at,
                fetched_at=fetched_at,
                raw_pub_date=raw_pub_date.strip() if isinstance(raw_pub_date, str) else None,
            )
        )
    logger.info("Fetched %d items", len(items))
    return items


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(entry: FeedEntry) -> dict:
    """Convert a FeedEntry to a SecLens bulletin dict."""
    origin_url = entry.link if _is_valid_url(entry.link) else None
    external_id = _derive_external_id(entry.guid, origin_url, entry.title)

    article_text = _fetch_article_body(origin_url)
    summary = None
    if article_text:
        summary = _generate_summary(article_text, limit=500)
    elif entry.description:
        summary = _clean_summary(entry.description)

    topics = ["official_bulletin"]
    labels = ["vendor:oracle"]
    extra: dict[str, object] = {
        "guid": entry.guid,
        "link": entry.link,
    }
    if entry.raw_pub_date:
        extra["raw_pub_date"] = entry.raw_pub_date

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
            "title": entry.title,
            "summary": summary,
            "body_text": article_text or entry.description,
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
                "title": entry.title,
                "link": entry.link,
                "description": entry.description,
                "published_at": entry.published_at,
                "guid": entry.guid,
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
    try:
        result = resp.json()
    except ValueError:
        result = {"status_code": resp.status_code}
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

    entries = fetch_feed()

    # Apply cursor-based dedup
    cursor = load_cursor()
    selected = []
    for entry in entries:
        if cursor and entry.published_at:
            try:
                entry_dt = datetime.fromisoformat(entry.published_at)
                if entry_dt <= cursor:
                    continue
            except ValueError:
                pass
        selected.append(entry)

    bulletins = [normalize(entry) for entry in selected]

    if not bulletins:
        logger.info("No items to push")
        return

    result = push_to_seclens(bulletins)

    # Update cursor with latest published_at
    latest_dt = None
    for entry in selected:
        if entry.published_at:
            try:
                dt = datetime.fromisoformat(entry.published_at)
                if latest_dt is None or dt > latest_dt:
                    latest_dt = dt
            except ValueError:
                pass
    if latest_dt:
        save_cursor(latest_dt)

    logger.info(
        "Done: %d fetched, %d accepted, %d duplicates",
        len(bulletins),
        result.get("accepted", 0),
        result.get("duplicates", 0),
    )


if __name__ == "__main__":
    main()
