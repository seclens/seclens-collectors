"""Chrome Stable Updates collector.

Fetches Chrome stable channel update posts from the Chrome Releases blog
and pushes them to a SecLens server. Fully standalone - no SecLens app dependencies.

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
    "CHROME_LIST_URL",
    "https://chromereleases.googleblog.com/search/label/Stable%20updates",
)
SOURCE_SLUG = "chrome_stable_updates"
USER_AGENT = "SeclensCollector/2.0 (chrome_stable_updates)"
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
    """Parameters controlling fetch behaviour for Chrome Stable updates."""

    list_url: str = LIST_URL
    limit: int | None = 10


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clean_text(value: str | None) -> str | None:
    if not value:
        return None
    normalised = unicodedata.normalize("NFKC", value)
    collapsed = " ".join(normalised.split())
    return collapsed or None


def _parse_date(text: str | None) -> datetime | None:
    if not text:
        return None
    candidate = _clean_text(text)
    if not candidate:
        return None
    for fmt in ("%A, %B %d, %Y", "%a, %B %d, %Y", "%B %d, %Y"):
        try:
            return datetime.strptime(candidate, fmt)
        except ValueError:
            continue
    return None


def _slugify(text: str) -> str:
    normalised = unicodedata.normalize("NFKD", text)
    result_chars: list[str] = []
    for char in normalised:
        if char.isalnum():
            result_chars.append(char.lower())
        elif char in {" ", "-", "_", "/"}:
            result_chars.append("-")
    slug = "".join(result_chars).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or "label"


def _extract_body_text(html: str | None) -> tuple[str | None, str | None]:
    if not html:
        return None, None
    soup = BeautifulSoup(html, "html.parser")
    chunks: list[str] = []
    seen: set[str] = set()
    for element in soup.find_all(["p", "li"]):
        text = _clean_text(element.get_text(" ", strip=True))
        if not text:
            continue
        if text in seen:
            continue
        seen.add(text)
        chunks.append(text)
    if not chunks:
        fallback = _clean_text(soup.get_text(" ", strip=True))
        if fallback:
            chunks.append(fallback)
    if not chunks:
        return None, None
    summary = chunks[0]
    body_text = "\n\n".join(chunks)
    return summary, body_text


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


def _parse_post(post: Tag, *, base_url: str) -> dict | None:
    if not isinstance(post, Tag):
        return None

    post_id = post.get("data-id")
    title_anchor = post.select_one("h2.title a")
    if not title_anchor or not title_anchor.get("href"):
        return None
    origin_url = urljoin(base_url, title_anchor["href"])
    title = _clean_text(title_anchor.get_text())
    if not title:
        title = origin_url

    publish_node = post.select_one(".post-header .publishdate")
    published_text = publish_node.get_text() if publish_node else None

    script_tag = post.select_one("div.post-content script[type='text/template']")
    body_html = None
    if script_tag and script_tag.string:
        body_html = script_tag.string
    elif script_tag:
        body_html = script_tag.get_text()
    if not body_html:
        noscript = post.select_one("div.post-content noscript")
        if noscript:
            body_html = noscript.decode_contents()

    summary, body_text = _extract_body_text(body_html)

    label_nodes = post.select("div.label-footer span.labels a.label")
    blog_labels: list[str] = []
    for node in label_nodes:
        label_text = _clean_text(node.get_text())
        if label_text:
            blog_labels.append(label_text)

    return {
        "post_id": post_id,
        "title": title,
        "origin_url": origin_url,
        "published_text": published_text,
        "body_html": body_html,
        "summary": summary,
        "body_text": body_text,
        "blog_labels": blog_labels,
    }


def fetch_listing(list_url: str = LIST_URL, limit: int | None = 10) -> list[dict]:
    """Fetch the Chrome Releases blog listing page and parse posts."""
    logger.info("Fetching listing: %s", list_url)
    response = requests.get(list_url, headers=REQUEST_HEADERS, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")
    container = soup.select_one("div.section#main div.widget.Blog")
    if not container:
        logger.warning("Unable to locate Blog container on %s", list_url)
        return []

    items: list[dict] = []
    for post in container.find_all("div", class_=lambda value: value and "post" in value.split(), recursive=False):
        parsed = _parse_post(post, base_url=list_url)
        if not parsed:
            continue
        items.append(parsed)
        if limit and len(items) >= limit:
            break
    logger.info("Fetched %d posts", len(items))
    return items


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(entry: dict) -> dict:
    """Convert a parsed post dict to a SecLens bulletin dict."""
    origin_url = entry.get("origin_url")
    if not origin_url:
        raise ValueError("origin_url missing in entry")

    fetched_at = now_utc_iso()

    candidates: list[tuple[object, str]] = []
    parsed_date = _parse_date(entry.get("published_text"))
    if parsed_date:
        candidates.append((parsed_date, "post.publishdate_parsed"))
    published_text = entry.get("published_text")
    if published_text:
        candidates.append((published_text, "post.publishdate_text"))

    published_at = parse_first(candidates, default_tz="UTC")

    external_id = entry.get("post_id") or origin_url.rsplit("/", 1)[-1]

    labels = ["vendor:google", "channel:stable"]
    for label in entry.get("blog_labels") or []:
        slug = _slugify(label)
        labels.append(f"blog-label:{slug}")

    topics = ["vendor-update"]

    extra: dict[str, object] = {
        "blog_labels": entry.get("blog_labels"),
        "body_html": entry.get("body_html"),
        "published_text": entry.get("published_text"),
    }

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": str(external_id),
            "origin_url": origin_url,
            "manifest": MANIFEST,
            "manifest_hash": MANIFEST_HASH,
            "manifest_version": MANIFEST_VERSION,
        },
        "content": {
            "title": entry.get("title") or origin_url,
            "summary": entry.get("summary"),
            "body_text": entry.get("body_text"),
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

    entries = fetch_listing(LIST_URL, limit=10)
    latest_cursor = str(entries[0].get("post_id") or entries[0].get("origin_url")) if entries else None
    previous_cursor = load_cursor()
    if previous_cursor:
        filtered: list[dict] = []
        for entry in entries:
            cursor_value = str(entry.get("post_id") or entry.get("origin_url") or "")
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
            logger.exception("Failed to normalise Chrome Stable entry: %s", entry, exc_info=exc)

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
