"""TC260 standard consultation collector - standalone version.

Scrapes consultation announcements from TC260 (National Information Security
Standardization Technical Committee) and pushes them to a SecLens server.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 4 hours (14400s)
"""
from __future__ import annotations

import logging
import os
import re
import sys
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

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

DEFAULT_LIST_URL = "https://www.tc260.org.cn/front/bzzqyjList.html"
DETAIL_BASE_URL = "https://www.tc260.org.cn"
SOURCE_SLUG = "tc260_consultations"
USER_AGENT = "SeclensCollector/2.0 (tc260_consultations)"
REQUEST_TIMEOUT = 30
REQUEST_HEADERS = {
    "User-Agent": USER_AGENT,
    "Referer": "https://www.tc260.org.cn/",
}
DEFAULT_TOPIC = "policy-compliance"
PAGE_SIZE = 10
STATE_FILE_NAME = ".cursor"
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return text or None


def _state_file_path() -> Path:
    return Path(__file__).resolve().parent / STATE_FILE_NAME


def load_cursor() -> str | None:
    path = _state_file_path()
    if not path.exists():
        return None
    value = path.read_text(encoding="utf-8").strip()
    return value or None


def save_cursor(cursor: str) -> None:
    path = _state_file_path()
    path.write_text(cursor.strip(), encoding="utf-8")


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


def fetch_list(list_url: str = DEFAULT_LIST_URL, limit: int | None = None) -> list[dict]:
    """Fetch consultation list from TC260 website."""
    session = requests.Session()
    session.headers.update(REQUEST_HEADERS)

    page_url = f"{list_url}?start=0&length={PAGE_SIZE}"
    logger.info("Fetching list: %s", page_url)
    response = session.get(page_url, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")
    items = soup.select("li.list-group-item.list_title_news")

    collected: list[dict] = []
    for li in items:
        anchor = li.find("a")
        if anchor is None or not anchor.get("href"):
            continue
        title = anchor.get_text(strip=True)
        detail_url = urljoin(DETAIL_BASE_URL, anchor["href"])
        deadline_node = li.find(class_="list_time")
        deadline = _clean_text(deadline_node.get_text(strip=True) if deadline_node else None)

        collected.append(
            {
                "title": title,
                "detail_url": detail_url,
                "deadline": deadline,
            }
        )
        if limit and len(collected) >= limit:
            break

    if limit:
        collected = collected[:limit]

    logger.info("Fetched %d items from list", len(collected))
    return collected


def fetch_detail(url: str) -> BeautifulSoup | None:
    """Fetch detail page content."""
    session = requests.Session()
    session.headers.update(REQUEST_HEADERS)
    response = session.get(url, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return BeautifulSoup(response.text, "html.parser")


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(item: dict) -> dict | None:
    """Normalize a TC260 consultation item to a SecLens bulletin dict."""
    try:
        detail_soup = fetch_detail(item["detail_url"])
    except requests.RequestException:
        logger.warning("Failed to fetch detail: %s", item["detail_url"])
        return None

    if detail_soup is None:
        return None

    content_node = detail_soup.select_one("div.news_end")
    if content_node is None:
        return None

    lines = [
        segment.strip()
        for segment in content_node.get_text("\n", strip=True).split("\n")
        if segment.strip()
    ]
    if not lines:
        return None

    # Determine published date
    published_raw = None
    for line in lines:
        match = re.search(r"\d{4}-\d{2}-\d{2}", line)
        if match:
            published_raw = match.group(0)
            break

    published_at = parse_first(
        [(published_raw, "detail.date")],
        default_tz="Asia/Shanghai",
    )

    body_text = "\n".join(lines)
    summary = "".join(lines[1:3]) if len(lines) > 1 else lines[0]
    summary = summary[:280]

    extra: dict = {
        "deadline": item.get("deadline"),
    }

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": item["detail_url"],
            "origin_url": item["detail_url"],
            "manifest": MANIFEST,
            "manifest_hash": MANIFEST_HASH,
            "manifest_version": MANIFEST_VERSION,
        },
        "content": {
            "title": item["title"],
            "summary": summary,
            "body_text": body_text,
            "published_at": published_at,
            "language": "zh",
        },
        "severity": None,
        "fetched_at": now_utc_iso(),
        "labels": [],
        "topics": [DEFAULT_TOPIC],
        "extra": extra,
        "raw": {
            "title": item["title"],
            "detail_url": item["detail_url"],
            "deadline": item.get("deadline"),
            "published_raw": published_raw,
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

    items = fetch_list()
    if not items:
        logger.info("No list items fetched")
        return

    newest_cursor = items[0]["detail_url"]
    cursor = load_cursor()
    if cursor:
        fresh_items: list[dict] = []
        for item in items:
            if item["detail_url"] == cursor:
                break
            fresh_items.append(item)
        logger.info("Cursor loaded: %s, %d new candidate items", cursor, len(fresh_items))
        items = fresh_items
    else:
        logger.info("No cursor found, treating current page as initial batch")

    if not items:
        logger.info("No new items since cursor, skip push")
        return

    bulletins = []
    for item in items:
        bulletin = normalize(item)
        if bulletin:
            bulletins.append(bulletin)

    if not bulletins:
        logger.info("No items to push")
        return

    result = push_to_seclens(bulletins)
    save_cursor(newest_cursor)
    logger.info(
        "Done: %d fetched, %d accepted, %d duplicates",
        len(bulletins),
        result.get("accepted", 0),
        result.get("duplicates", 0),
    )


if __name__ == "__main__":
    main()
