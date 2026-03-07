"""Antiy SafeInfo collector - standalone version.

Fetches security announcements from Antiy SafeInfo daily briefing API
and pushes them to a SecLens server.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 4 hours (14400s)
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime
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

DETAIL_API_URL_TEMPLATE = "https://www.antiycloud.com/api/dailyDetail/{daily_time}"
SOURCE_SLUG = "antiy_safeinfor"
USER_AGENT = "SeclensCollector/2.0 (antiy_safeinfor)"
REQUEST_TIMEOUT = 30
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)
DEFAULT_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Content-Type": "application/json",
    "Origin": "https://www.antiycloud.com",
    "Referer": "https://www.antiycloud.com/",
    "User-Agent": USER_AGENT,
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

CACHE_FILE = Path(__file__).parent / ".cursor"


def _load_cache() -> set:
    """Load processed item IDs cache from file."""
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, encoding='utf-8') as f:
                data = json.load(f)
                return set(data.get('ids', []))
        except (json.JSONDecodeError, KeyError):
            return set()
    return set()


def _save_cache(ids: set) -> None:
    """Save processed item IDs cache to file."""
    with open(CACHE_FILE, 'w', encoding='utf-8') as f:
        json.dump({'ids': list(ids)}, f, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


def fetch_detail(daily_time: str) -> dict | None:
    """Fetch detailed content from the daily detail API."""
    detail_api_url = DETAIL_API_URL_TEMPLATE.format(daily_time=daily_time)
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    try:
        response = session.post(detail_api_url, json=None, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        body = response.json()

        if body.get("status") == "success":
            return body
        else:
            logger.warning("Antiy detail API returned non-success status: %s", body.get('status'))
            return None
    except Exception as e:
        logger.warning("Failed to fetch detail for %s: %s", daily_time, e)
        return None


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(item: dict, daily_time: str) -> dict | None:
    """Normalize a security announcement item to a SecLens bulletin dict."""
    cache = _load_cache()

    title = item.get("title", "")
    description = item.get("description", "")
    tags = item.get("tags", [])
    refer = item.get("refer", [])
    event_time = item.get("event_time", "")

    # Create a unique ID based on title and date for deduplication
    item_id = f"{title[:50]}_{daily_time}" if title else f"entry_{daily_time}"

    # Skip duplicates
    if item_id in cache:
        return None

    # Mark as processed
    cache.add(item_id)
    _save_cache(cache)

    full_title = f"{daily_time}-{title}" if title else f"{daily_time}-安全简讯"

    published_at = parse_first(
        [
            (event_time, "item.event_time"),
            (f"{daily_time} 06:00", "daily_time with default time"),
        ],
        default_tz="Asia/Shanghai",
    )

    origin_url = f"https://www.antiycloud.com/#/dailydetail/{daily_time}?keyword=" if daily_time else None

    labels = ["antiy", "security_announcement"]
    labels.extend([f"tag:{tag}" for tag in tags if tag])
    if daily_time:
        labels.append(f"daily:{daily_time}")

    extra: dict = {
        "daily_time": daily_time,
        "tags": tags,
        "refer": refer,
        "event_time": event_time,
        "original_title": title,
    }

    raw = dict(item)
    raw["daily_time"] = daily_time

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": item_id,
            "origin_url": origin_url,
            "manifest": MANIFEST,
            "manifest_hash": MANIFEST_HASH,
            "manifest_version": MANIFEST_VERSION,
        },
        "content": {
            "title": full_title,
            "summary": description[:200] if description else full_title[:200],
            "body_text": description,
            "published_at": published_at,
            "language": "zh-CN",
        },
        "severity": None,
        "fetched_at": now_utc_iso(),
        "labels": labels,
        "topics": ["official_bulletin", "security_announcement"],
        "extra": extra,
        "raw": raw,
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

    daily_time = os.environ.get("ANTIY_DAILY_TIME") or datetime.now().strftime("%Y%m%d")
    logger.info("Fetching Antiy SafeInfo for date: %s", daily_time)

    data = fetch_detail(daily_time)
    if not data:
        logger.info("No data returned for %s", daily_time)
        return

    items = data.get("data", {}).get("content", [])
    if not isinstance(items, list):
        logger.info("No content items found")
        return

    bulletins = []
    for item in items:
        if isinstance(item, dict):
            bulletin = normalize(item, daily_time)
            if bulletin is not None:
                bulletins.append(bulletin)

    if not bulletins:
        logger.info("No new items to push")
        return

    result = push_to_seclens(bulletins)
    logger.info(
        "Done: fetched=%d accepted=%s duplicates=%s",
        len(bulletins),
        result.get("accepted", 0),
        result.get("duplicates", 0),
    )


if __name__ == "__main__":
    main()
