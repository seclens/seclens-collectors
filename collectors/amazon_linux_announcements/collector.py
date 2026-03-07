"""Amazon Linux security announcements HTML table collector.

Fetches security announcements from the Amazon Linux announcements page
and pushes them to a SecLens server. Fully standalone - no SecLens app
dependencies.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 2 hours (7200s)
"""
from __future__ import annotations

import logging
import os
import sys
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup, Tag

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
LIST_URL = os.environ.get(
    "ALAS_ANNOUNCEMENTS_URL", "https://alas.aws.amazon.com/announcements.html"
)
BASE_URL = "https://alas.aws.amazon.com/"
SOURCE_SLUG = "amazon_linux_announcements"
USER_AGENT = "SeclensCollector/2.0 (amazon_linux_announcements)"
REQUEST_TIMEOUT = 30
STATE_FILE_NAME = ".cursor"
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)

REQUEST_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "User-Agent": USER_AGENT,
}


@dataclass
class FetchParams:
    list_url: str = LIST_URL
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


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    candidate = _clean_text(value)
    if not candidate:
        return None
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(candidate, fmt)
        except ValueError:
            continue
    return None


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


class AmazonLinuxAnnouncementsCollector:
    """Fetch and normalise Amazon Linux security announcements."""

    def __init__(self, session: requests.Session | None = None) -> None:
        self.session = session or requests.Session()
        self.session.headers.update(REQUEST_HEADERS)

    def fetch(self, params: FetchParams) -> Sequence[dict]:
        response = self.session.get(params.list_url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        table = soup.select_one("div.aws-table table#ALAStable tbody")
        if not table:
            logger.warning("Announcements table not found at %s", params.list_url)
            return []

        items: list[dict] = []
        for row in table.find_all("tr"):
            parsed = self._parse_row(row, base_url=params.list_url)
            if not parsed:
                continue
            items.append(parsed)
            if params.limit and len(items) >= params.limit:
                break
        logger.info("Fetched %d items from announcements page", len(items))
        return items

    def _parse_row(self, row: Tag, *, base_url: str) -> dict | None:
        cells = row.find_all("td")
        if len(cells) != 3:
            return None
        published_text = _clean_text(cells[0].get_text(" ", strip=True))
        updated_text = _clean_text(cells[1].get_text(" ", strip=True))
        announcement_cell = cells[2]

        links = announcement_cell.find_all("a", href=True)
        if not links:
            return None
        announcement_id = _clean_text(links[0].get_text(" ", strip=True))
        title = _clean_text(links[-1].get_text(" ", strip=True))
        href = links[-1]["href"]
        origin_url = urljoin(base_url, href)

        published_dt = _parse_timestamp(published_text)
        updated_dt = _parse_timestamp(updated_text)

        return {
            "announcement_id": announcement_id,
            "title": title,
            "origin_url": origin_url,
            "published_text": published_text,
            "updated_text": updated_text,
            "published_dt": published_dt,
            "updated_dt": updated_dt,
        }


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(entry: dict) -> dict:
    """Convert a parsed announcement entry to SecLens bulletin dict."""
    fetched_at = now_utc_iso()

    candidates = []
    if entry.get("published_dt"):
        candidates.append((entry["published_dt"], "table.published_datetime"))
    if entry.get("published_text"):
        candidates.append((entry["published_text"], "table.published_text"))

    published_at = parse_first(candidates, default_tz="UTC")

    announcement_id = entry.get("announcement_id") or entry.get("title")
    title = entry.get("title") or announcement_id or entry.get("origin_url")

    summary_parts = []
    if entry.get("announcement_id"):
        summary_parts.append(entry["announcement_id"])
    if entry.get("title") and entry.get("announcement_id") != entry.get("title"):
        summary_parts.append(entry["title"])
    summary = " - ".join(summary_parts) or entry.get("title")

    body_lines = []
    if entry.get("published_text"):
        body_lines.append(f"Published: {entry['published_text']}")
    if entry.get("updated_text"):
        body_lines.append(f"Last Updated: {entry['updated_text']}")
    if entry.get("title"):
        body_lines.append(entry["title"])
    body_text = "\n".join(body_lines) or None

    labels = ["vendor:aws", "distribution:amazon-linux", "announcement"]
    if announcement_id:
        labels.append(f"announcement:{announcement_id.lower()}")

    labels = [_clean_text(label) for label in labels if _clean_text(label)]

    topics = ["vendor-update", "official_advisory"]

    extra: dict[str, object] = {
        "announcement_id": announcement_id,
        "published_text": entry.get("published_text"),
        "updated_text": entry.get("updated_text"),
    }
    if entry.get("updated_dt"):
        extra["updated_at"] = entry["updated_dt"].isoformat()

    raw_payload = dict(entry)
    if entry.get("published_dt"):
        raw_payload["published_dt"] = entry["published_dt"].isoformat()
    if entry.get("updated_dt"):
        raw_payload["updated_dt"] = entry["updated_dt"].isoformat()

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": str(announcement_id or entry.get("origin_url")),
            "origin_url": entry.get("origin_url"),
            "manifest": MANIFEST,
            "manifest_hash": MANIFEST_HASH,
            "manifest_version": MANIFEST_VERSION,
        },
        "content": {
            "title": title,
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

    collector = AmazonLinuxAnnouncementsCollector()
    entries = collector.fetch(FetchParams(list_url=LIST_URL))
    latest_cursor = str(entries[0].get("announcement_id") or entries[0].get("origin_url")) if entries else None
    previous_cursor = load_cursor()
    if previous_cursor:
        filtered: list[dict] = []
        for entry in entries:
            cursor_value = str(entry.get("announcement_id") or entry.get("origin_url") or "")
            if cursor_value == previous_cursor:
                break
            filtered.append(entry)
        entries = filtered
        logger.info(
            "Cursor check: previous=%s, pending=%d",
            previous_cursor,
            len(entries),
        )

    bulletins = []
    for entry in entries:
        try:
            bulletins.append(normalize(entry))
        except Exception as exc:
            logger.exception("Failed to normalise Amazon Linux announcement: %s", entry, exc_info=exc)

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
