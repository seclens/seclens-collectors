"""Aliyun security bulletin collector.

Fetches security bulletins from the Aliyun public API and pushes them
to a SecLens server. Fully standalone - no SecLens app dependencies.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 1 hour (3600s)
"""
from __future__ import annotations

import json
import logging
import os
import sys
from collections.abc import Iterable, Sequence
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

API_URL = "https://t.aliyun.com/abs/bulletin/bulletinQuery"
DEFAULT_PAGE_SIZE = 50
SOURCE_SLUG = "aliyun_security"
USER_AGENT = "SeclensCollector/2.0 (aliyun_security)"
REQUEST_TIMEOUT = 30
STATE_FILE_NAME = ".cursor"
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
# Fetch
# ---------------------------------------------------------------------------


@dataclass
class FetchParams:
    """Pagination and filtering settings for the Aliyun API."""

    page_no: int = 1
    page_size: int = DEFAULT_PAGE_SIZE
    bulletin_type: str = "security"


def fetch_bulletins(params: FetchParams | None = None) -> Sequence[dict]:
    """Fetch bulletins from the Aliyun API."""
    params = params or FetchParams()
    logger.info(
        "Fetching Aliyun bulletins (page=%d, size=%d, type=%s)",
        params.page_no, params.page_size, params.bulletin_type,
    )
    session = requests.Session()
    session.headers.update(
        {
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://www.aliyun.com",
            "Referer": "https://www.aliyun.com/",
            "User-Agent": USER_AGENT,
        }
    )
    response = session.get(
        API_URL,
        params={
            "pageNo": params.page_no,
            "pageSize": params.page_size,
            "bulletinType": params.bulletin_type,
        },
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    payload = response.json()
    info = payload.get("data", {}).get("info", [])
    if not isinstance(info, Iterable):
        logger.warning("Unexpected payload structure from Aliyun: %s", payload)
        return []
    items = list(info)
    logger.info("Fetched %d items", len(items))
    return items


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(item: dict) -> dict:
    """Convert a raw Aliyun bulletin dict to a SecLens bulletin dict."""
    published_at = parse_first(
        [
            (item.get("publishTime"), "item.publishTime"),
            (item.get("publishDate"), "item.publishDate"),
        ],
        default_tz="Asia/Shanghai",
    )

    title = item.get("titleFill") or item.get("title") or ""
    origin_url = item.get("url")
    summary = item.get("summary")
    content = item.get("content")
    if not summary and isinstance(content, str):
        summary = content[:280]

    labels: list[str] = []
    for key in ("bulletinType", "bulletinType2", "bulletinType3", "bulletinType4", "bulletinType5"):
        value = item.get(key)
        if value:
            labels.append(value)

    extra: dict = {
        "bulletin_type": item.get("bulletinType"),
        "bulletin_type_detail": item.get("bulletinType2"),
        "impact_time": item.get("impactTime"),
        "impact_time_type": item.get("impactTimeType"),
        "status": item.get("status"),
        "product_code": item.get("productCode"),
        "product_info": item.get("productInfo"),
        "language": item.get("language"),
    }
    ext_info = item.get("extInfo")
    if isinstance(ext_info, str):
        try:
            extra["ext_info"] = json.loads(ext_info)
        except json.JSONDecodeError:
            extra["ext_info"] = ext_info
    elif isinstance(ext_info, dict):
        extra["ext_info"] = ext_info

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": str(item.get("id")) if item.get("id") is not None else None,
            "origin_url": origin_url,
            "manifest": MANIFEST,
            "manifest_hash": MANIFEST_HASH,
            "manifest_version": MANIFEST_VERSION,
        },
        "content": {
            "title": title,
            "summary": summary,
            "body_text": content,
            "published_at": published_at,
            "language": item.get("language"),
        },
        "severity": item.get("securityLevel"),
        "fetched_at": now_utc_iso(),
        "labels": labels,
        "topics": ["official_bulletin"],
        "extra": extra,
        "raw": item,
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

    items = fetch_bulletins()
    latest_cursor = str(items[0].get("id")) if items and items[0].get("id") is not None else None
    previous_cursor = load_cursor()
    if previous_cursor:
        filtered_items: list[dict] = []
        for item in items:
            item_id = item.get("id")
            cursor_value = str(item_id) if item_id is not None else ""
            if cursor_value == previous_cursor:
                break
            filtered_items.append(item)
        items = filtered_items
        logger.info(
            "Cursor check: previous=%s, pending=%d",
            previous_cursor,
            len(items),
        )

    bulletins = [normalize(item) for item in items]

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
