"""CNNVD Announcement Database Collector (standalone).

Fetches vulnerability announcement information from China National Vulnerability
Database (CNNVD) warning/announcement section.

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
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

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

SOURCE_SLUG = "cnnvd_announcement"
LIST_API_URL = "https://www.cnnvd.org.cn/web/homePage/vulWarnList"
DETAIL_API_URL = "https://www.cnnvd.org.cn/web/homePage/vulWarnDetail"
USER_AGENT = "SeclensCollector/2.0 (cnnvd_announcement)"
REQUEST_TIMEOUT = 30
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)

DEFAULT_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Content-Type": "application/json;charset=UTF-8",
    "Origin": "https://www.cnnvd.org.cn",
    "Referer": "https://www.cnnvd.org.cn/home/warn",
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
# Fetch Parameters
# ---------------------------------------------------------------------------

@dataclass
class FetchParams:
    """Parameters for fetching CNNVD announcement data."""
    page_index: int = 1
    page_size: int = 20
    keyword: str = ""
    report_type: int = 1
    begin_time: str = ""
    end_time: str = ""
    date_type: str = ""


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class CNNVDAnnouncementCollector:
    """Fetch and normalize CNNVD announcement data."""

    def __init__(self, session: requests.Session | None = None) -> None:
        self.session = session or requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self.cache_file = Path(__file__).parent / ".cursor"
        self._last_stats: dict[str, int] = {
            "items_processed": 0,
            "items_skipped_cache": 0,
            "items_created": 0,
        }

    def _load_cache(self) -> set:
        """Load processed warnId cache from file."""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, encoding='utf-8') as f:
                    data = json.load(f)
                    return set(data.get('warn_ids', []))
            except (json.JSONDecodeError, KeyError):
                return set()
        return set()

    def _save_cache(self, warn_ids: set) -> None:
        """Save processed warnId cache to file."""
        with open(self.cache_file, 'w', encoding='utf-8') as f:
            json.dump({'warn_ids': list(warn_ids)}, f, ensure_ascii=False)

    def _is_processed(self, warn_id: str) -> bool:
        cache = self._load_cache()
        return warn_id in cache

    def _mark_processed(self, warn_id: str) -> None:
        cache = self._load_cache()
        cache.add(warn_id)
        self._save_cache(cache)

    def fetch_list(self, params: FetchParams) -> Sequence[dict]:
        """Fetch announcement list from CNNVD."""
        payload = {
            "pageIndex": params.page_index,
            "pageSize": params.page_size,
            "keyword": params.keyword,
            "reportType": params.report_type,
            "beginTime": params.begin_time,
            "endTime": params.end_time,
            "dateType": params.date_type,
            "begin": None,
            "end": None,
        }

        response = self.session.post(LIST_API_URL, json=payload, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        body = response.json()

        if body.get("code") != 200:
            logger.warning("CNNVD announcement API returned non-200 code: %s", body.get("code"))
            return []

        data = body.get("data")
        if not data:
            return []

        records = data.get("records", [])
        if not isinstance(records, list):
            return []

        return records

    def fetch_detail(self, warn_id: str) -> dict | None:
        """Fetch detailed announcement information using multipart form data."""
        boundary = "----WebKitFormBoundaryKNzU6jcmBYhNIOmn"
        body = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"warnId\"\r\n\r\n"
            f"{warn_id}\r\n"
            f"--{boundary}--\r\n"
        )

        headers = dict(self.session.headers)
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"

        try:
            response = self.session.post(
                DETAIL_API_URL,
                data=body,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            resp_body = response.json()

            if resp_body.get("code") != 200:
                logger.warning("CNNVD announcement detail API returned non-200 code: %s for warn_id %s", resp_body.get("code"), warn_id)
                return None

            data = resp_body.get("data", {})
            return data
        except Exception as e:
            logger.warning("Failed to fetch detail for announcement %s: %s", warn_id, e)
            return None

    def normalize(self, item: dict) -> dict | None:
        """Normalize announcement data to bulletin dict. Returns None for cached items."""
        fetched_at = now_utc_iso()

        warn_id = item.get("warnId")
        warn_name = item.get("warnName", "")
        publish_time = item.get("publishTime")
        create_uname = item.get("createUname")

        # Skip already processed items
        if self._is_processed(warn_id):
            return None

        # Fetch detailed information
        detail_data = None
        enclosure_content = ""
        if warn_id:
            detail_data = self.fetch_detail(warn_id)
            if detail_data:
                enclosure_content = detail_data.get("enclosureContent", "")

        # Parse HTML content for summary
        summary = ""
        if enclosure_content:
            soup = BeautifulSoup(enclosure_content, 'html.parser')
            text_content = soup.get_text()
            summary = text_content[:200].strip()

        # Determine publication time
        published_at = parse_first(
            [
                (detail_data.get("publishTime") if detail_data else None, "detail.publishTime"),
                (publish_time, "item.publishTime"),
            ],
            default_tz="Asia/Shanghai",
        )

        # Mark as processed
        self._mark_processed(warn_id)

        origin_url = "https://www.cnnvd.org.cn/home/warn"

        # Build labels
        labels = ["cnnvd", "cnnvd_announcement"]
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        title_cves = re.findall(cve_pattern, warn_name)
        content_cves = re.findall(cve_pattern, enclosure_content)
        all_cves = set(title_cves + content_cves)
        for cve in all_cves:
            labels.append(f"cve:{cve}")

        topics = ["official_bulletin", "vulnerability_alert", "cnnvd_announcement"]

        extra: dict[str, object] = {
            "warn_id": warn_id,
            "create_uname": create_uname,
            "warn_name": warn_name,
            "publish_time": publish_time,
        }

        if detail_data:
            extra.update({
                "detailed_publish_time": detail_data.get("publishTime"),
                "detailed_warn_name": detail_data.get("warnName"),
                "detailed_create_user": detail_data.get("createUname"),
            })

        raw = dict(item)
        if detail_data:
            raw["detail"] = detail_data

        return {
            "source": {
                "source_slug": SOURCE_SLUG,
                "external_id": warn_id,
                "origin_url": origin_url,
                "manifest": MANIFEST,
                "manifest_hash": MANIFEST_HASH,
                "manifest_version": MANIFEST_VERSION,
            },
            "content": {
                "title": warn_name,
                "summary": summary if summary else warn_name[:200],
                "body_text": enclosure_content,
                "published_at": published_at,
                "language": "zh-CN",
            },
            "severity": "info",
            "fetched_at": fetched_at,
            "labels": labels,
            "topics": topics,
            "extra": extra,
            "raw": raw,
        }

    def collect(self, params: FetchParams | None = None) -> list[dict]:
        """Collect and normalize CNNVD announcement data."""
        params = params or FetchParams()
        items = self.fetch_list(params)
        bulletins: list[dict] = []
        total_processed = 0
        skipped_from_cache = 0

        for item in items:
            total_processed += 1
            bulletin = self.normalize(item)
            if bulletin is None:
                skipped_from_cache += 1
                continue
            bulletins.append(bulletin)

        self._last_stats = {
            "items_processed": total_processed,
            "items_skipped_cache": skipped_from_cache,
            "items_created": len(bulletins),
        }
        return bulletins


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

    collector = CNNVDAnnouncementCollector()
    bulletins = collector.collect()

    if not bulletins:
        logger.info("No items to push")
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
