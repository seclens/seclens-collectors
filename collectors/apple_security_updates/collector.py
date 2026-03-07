"""Apple Security Updates collector.

Fetches Apple security release information from the Apple Support advisory
list and pushes them to a SecLens server. Fully standalone - no SecLens app
dependencies.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 4 hours (14400s)
"""
from __future__ import annotations

import logging
import os
import sys
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

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
    "APPLE_LIST_URL", "https://support.apple.com/en-us/100100"
)
BASE_URL = "https://support.apple.com"
SOURCE_SLUG = "apple_security_updates"
USER_AGENT = "SeclensCollector/2.0 (apple_security_updates)"
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
    """Parameters controlling Apple security releases fetching."""

    list_url: str = LIST_URL
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


def _slugify(text: str | None) -> str:
    if not text:
        return "entry"
    normalised = unicodedata.normalize("NFKD", text)
    result: list[str] = []
    for char in normalised:
        if char.isalnum():
            result.append(char.lower())
        elif char in {" ", "-", "_", "/", "."}:
            result.append("-")
    slug = "".join(result).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or "entry"


def _parse_release_date(text: str | None) -> datetime | None:
    if not text:
        return None
    candidate = _clean_text(text)
    if not candidate:
        return None
    for fmt in ("%d %b %Y", "%d %B %Y"):
        try:
            return datetime.strptime(candidate, fmt)
        except ValueError:
            continue
    return None


def _extract_notes(cell: Tag) -> list[str]:
    notes: list[str] = []
    for note in cell.select(".note"):
        text = _clean_text(note.get_text(" ", strip=True))
        if text:
            notes.append(text)
    return notes


def _primary_cell_text(cell: Tag) -> str | None:
    for paragraph in cell.find_all("p", class_="gb-paragraph"):
        parent = paragraph.parent
        classes = parent.get("class", []) if isinstance(parent, Tag) else []
        if any(cls for cls in classes if "note" in cls):
            continue
        text = _clean_text(paragraph.get_text(" ", strip=True))
        if text:
            return text
    text = _clean_text(cell.get_text(" ", strip=True))
    return text


def _dedupe_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _external_id(detail_url: str | None, title: str | None) -> str:
    if detail_url:
        parsed = urlparse(detail_url)
        fragment = parsed.path.rstrip("/").rsplit("/", 1)[-1]
        if fragment:
            return fragment
    return _slugify(title)


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


def _parse_row(cells: list[Tag], *, base_url: str) -> dict | None:
    name_cell, availability_cell, released_cell = cells

    anchor = name_cell.find("a", href=True)
    detail_url = None
    title = None
    if anchor:
        href = anchor.get("href")
        detail_url = urljoin(BASE_URL, href)
        title = _clean_text(anchor.get_text(" ", strip=True))
    if not title:
        title = _primary_cell_text(name_cell)
    if not title:
        return None

    notes = _extract_notes(name_cell)

    available_for = _clean_text(availability_cell.get_text(" ", strip=True))
    release_text = _clean_text(released_cell.get_text(" ", strip=True))

    external_id_val = _external_id(detail_url, title)
    origin_url = detail_url or f"{base_url}#{external_id_val}"

    return {
        "external_id": external_id_val,
        "title": title,
        "origin_url": origin_url,
        "detail_url": detail_url,
        "available_for": available_for,
        "release_text": release_text,
        "notes": notes,
    }


def fetch_listing(list_url: str = LIST_URL, limit: int | None = 20) -> list[dict]:
    """Fetch the Apple security releases table."""
    logger.info("Fetching listing: %s", list_url)
    response = requests.get(list_url, headers=REQUEST_HEADERS, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")
    table = soup.select_one("div.table-wrapper.gb-table table.gb-table")
    if not table:
        logger.warning("Apple security releases table not found at %s", list_url)
        return []

    entries: list[dict] = []
    seen_ids: set[str] = set()
    for row in table.find_all("tr")[1:]:
        cells = row.find_all("td")
        if len(cells) != 3:
            continue
        parsed = _parse_row(cells, base_url=list_url)
        if not parsed:
            continue
        identifier = parsed.get("external_id")
        if identifier and identifier in seen_ids:
            continue
        if identifier:
            seen_ids.add(identifier)
        entries.append(parsed)
        if limit and len(entries) >= limit:
            break
    logger.info("Fetched %d entries", len(entries))
    return entries


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(entry: dict) -> dict:
    """Convert a parsed entry dict to a SecLens bulletin dict."""
    fetched_at = now_utc_iso()

    release_text = entry.get("release_text")
    parsed_date = _parse_release_date(release_text)

    candidates: list[tuple[object, str]] = []
    if parsed_date:
        candidates.append((parsed_date, "table.release_date_parsed"))
    if release_text:
        candidates.append((release_text, "table.release_date_text"))

    published_at = parse_first(candidates, default_tz="UTC")

    notes: list[str] = entry.get("notes") or []
    available_for = entry.get("available_for")

    summary_parts: list[str] = []
    if available_for:
        summary_parts.append(available_for)
    if notes:
        summary_parts.append("; ".join(notes))
    summary = " | ".join(summary_parts) or None

    body_lines: list[str] = []
    if available_for:
        body_lines.append(f"Available for: {available_for}")
    for note in notes:
        body_lines.append(note)
    if release_text:
        body_lines.append(f"Release date: {release_text}")
    body_text = "\n".join(body_lines) or None

    title = entry.get("title") or entry.get("origin_url")

    labels = ["vendor:apple"]
    if title:
        labels.append(f"product:{_slugify(title)}")
    for note in notes:
        if "no published cve" in note.lower():
            labels.append("note:no-cve")

    labels = _dedupe_order(label for label in labels if label)

    topics = ["vendor-update", "official_advisory"]

    extra: dict[str, object] = {
        "available_for": available_for,
        "notes": notes,
        "release_date_text": release_text,
        "detail_url": entry.get("detail_url"),
    }

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": str(entry.get("external_id")),
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

    entries = fetch_listing(LIST_URL, limit=20)
    latest_cursor = str(entries[0]["external_id"]) if entries else None
    previous_cursor = load_cursor()
    if previous_cursor:
        filtered: list[dict] = []
        for entry in entries:
            if str(entry.get("external_id") or "") == previous_cursor:
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
            logger.exception("Failed to normalise Apple security entry: %s", entry, exc_info=exc)

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
