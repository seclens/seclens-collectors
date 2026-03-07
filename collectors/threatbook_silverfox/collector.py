"""ThreatBook SilverFox Intelligence Collector (standalone).

Fetches threat intelligence from ThreatBook SilverFox platform, including
APT events, phishing events, data theft, and attack activity analysis.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 2 hours (7200s)
"""
# ruff: noqa: UP006,UP035,UP045,UP017,UP015,F401
from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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

SOURCE_SLUG = "threatbook_silverfox"
LIST_API_URL = "https://s.threatbook.com/apis/cybercrime-trend/get-humans"
DETAIL_API_URL_TEMPLATE = "https://s.threatbook.com/apis/cybercrime-trend/get-human?uuid={uuid}"
DETAIL_PAGE_URL_TEMPLATE = "https://s.threatbook.com/blog/attack/{uuid}.html"
USER_AGENT = "SeclensCollector/2.0 (threatbook_silverfox)"
REQUEST_TIMEOUT = 30

CACHE_FILE = ".cursor"
CACHE_LIMIT = 100
INGEST_BATCH_SIZE = 10
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)
DEFAULT_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


# ---------------------------------------------------------------------------
# Cache Management
# ---------------------------------------------------------------------------

def load_cache() -> set:
    """Load processed UUIDs from cache file."""
    cache_path = Path(__file__).parent / CACHE_FILE
    try:
        with open(cache_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return set(data.get('uuids', []))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()


def save_cache(uuids: set) -> None:
    """Save processed UUIDs to cache file, trimmed to cache limit."""
    cache_path = Path(__file__).parent / CACHE_FILE
    trimmed_uuids = list(uuids)[-CACHE_LIMIT:] if len(uuids) > CACHE_LIMIT else list(uuids)
    with open(cache_path, 'w', encoding='utf-8') as f:
        json.dump({'uuids': trimmed_uuids}, f, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class ThreatBookSilverFoxCollector:
    """Fetch and normalize ThreatBook SilverFox intelligence data."""

    def __init__(self, session: requests.Session | None = None) -> None:
        self.session = session or requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self.cache = load_cache()

    def fetch_list(self, days_back: int = 30) -> List[Dict[str, Any]]:
        """Fetch list of intelligence reports from the past N days."""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days_back)

        start_ms = int(start_time.timestamp() * 1000)
        end_ms = int(end_time.timestamp() * 1000)

        url = f"{LIST_API_URL}?startTime={start_ms}&endTime={end_ms}"

        try:
            response = self.session.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            body = response.json()
            items = body.get("data", {}).get("data", [])
            logger.info("[ThreatBook SilverFox] Fetched %d items from list API", len(items))
            return items if isinstance(items, list) else []
        except Exception as e:
            logger.error("[ThreatBook SilverFox] Failed to fetch list: %s", e)
            return []

    def fetch_detail(self, uuid: str) -> Dict[str, Any] | None:
        """Fetch detailed intelligence report by UUID."""
        url = DETAIL_API_URL_TEMPLATE.format(uuid=uuid)

        try:
            response = self.session.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            body = response.json()
            data = body.get("data")
            if data:
                logger.info("[ThreatBook SilverFox] Fetched detail for UUID: %s", uuid)
                return data
            else:
                logger.warning("[ThreatBook SilverFox] No data in detail response for UUID: %s", uuid)
                return None
        except Exception as e:
            logger.warning("[ThreatBook SilverFox] Failed to fetch detail for %s: %s", uuid, e)
            return None

    def normalize(self, detail: Dict[str, Any]) -> dict | None:
        """Normalize intelligence data to bulletin dict."""
        fetched_at = now_utc_iso()

        uuid = detail.get("uuid")
        if not uuid:
            logger.warning("[ThreatBook SilverFox] Missing UUID, skipping item")
            return None

        title = detail.get("title", "未知标题")
        report_time_ms = detail.get("report_time")
        event_types = detail.get("event_type", [])
        gpt_tags = detail.get("gpt_tags") or []
        related_anonymous = detail.get("related_anonymous")

        # Build summary from summary_v2
        summary_v2 = detail.get("summary_v2") or {}
        summary_content = summary_v2.get("content", "")
        if not summary_content:
            summary_content = title
        title = str(title)[:500]
        summary_content = str(summary_content)[:2000]

        # Build body_text from main_conclusions_v2
        main_conclusions = detail.get("main_conclusions_v2") or {}
        body_parts = []
        if main_conclusions.get("result_background"):
            body_parts.append(f"## 事件背景\n{main_conclusions['result_background']}\n")
        if main_conclusions.get("result_attack"):
            body_parts.append(f"## 攻击手法\n{main_conclusions['result_attack']}\n")
        if main_conclusions.get("result_impact"):
            body_parts.append(f"## 影响评估\n{main_conclusions['result_impact']}\n")
        if main_conclusions.get("result_measure"):
            body_parts.append(f"## 处置建议\n{main_conclusions['result_measure']}\n")

        body_text = "\n".join(body_parts) if body_parts else summary_content

        # Parse published_at
        published_at = parse_first(
            [
                (report_time_ms / 1000 if report_time_ms else None, "item.report_time"),
                (detail.get("event_date"), "item.event_date"),
            ],
            default_tz="Asia/Shanghai",
        )

        origin_url = DETAIL_PAGE_URL_TEMPLATE.format(uuid=uuid)

        # Build labels
        labels = ["threatbook", "silverfox", "threat_intelligence"]
        labels.extend([f"event:{et}" for et in event_types if et])
        if related_anonymous:
            labels.append(f"group:{related_anonymous}")
        labels.extend([f"tag:{tag}" for tag in gpt_tags if tag])
        labels = [str(label)[:100] for label in labels if label][:50]

        # Build topics
        topics = ["threat_intelligence"]
        if "APT事件" in event_types:
            topics.append("apt")
        if "网络钓鱼事件" in event_types:
            topics.append("phishing")
        if "数据窃取事件" in event_types:
            topics.append("data_theft")
        if "勒索软件事件" in event_types:
            topics.append("ransomware")

        # Determine severity based on impact_content
        impact_content = detail.get("impact_content") or []
        severity = None
        if len(impact_content) >= 4:
            severity = "critical"
        elif len(impact_content) >= 2:
            severity = "high"
        elif len(impact_content) >= 1:
            severity = "medium"

        # Build extra data
        extra: Dict[str, Any] = {
            "event_types": event_types,
            "gpt_tags": gpt_tags,
            "related_anonymous": related_anonymous,
            "target_country": detail.get("target_country"),
            "target_industry_type": detail.get("target_industry_type"),
            "target_area": detail.get("target_area"),
            "malware_name": detail.get("malware_name"),
        }

        # Add IOC information
        ioc_list = detail.get("related_ioc_list_v2") or {}
        if any(ioc_list.values()):
            extra["ioc"] = {k: v for k, v in ioc_list.items() if v}

        # Add attack methods
        attack_method = detail.get("attack_method_v2") or {}
        if attack_method:
            extra["attack_method"] = {
                "is_new_attack": attack_method.get("is_new_attack"),
                "is_command": attack_method.get("is_command"),
                "attack_type": attack_method.get("attack_type"),
                "attck_count": len(attack_method.get("attck") or []),
            }

        # Add reference links
        reference_links = detail.get("reference_link")
        if reference_links:
            extra["reference_links"] = reference_links if isinstance(reference_links, list) else [reference_links]

        return {
            "source": {
                "source_slug": SOURCE_SLUG,
                "external_id": uuid,
                "origin_url": origin_url,
                "manifest": MANIFEST,
                "manifest_hash": MANIFEST_HASH,
                "manifest_version": MANIFEST_VERSION,
            },
            "content": {
                "title": title,
                "summary": summary_content[:500] if len(summary_content) > 500 else summary_content,
                "body_text": body_text,
                "published_at": published_at,
                "language": "zh-CN",
            },
            "severity": severity,
            "fetched_at": fetched_at,
            "labels": labels,
            "topics": topics,
            "extra": extra,
            "raw": dict(detail),
        }

    def collect(self, days_back: int = 30) -> List[dict]:
        """Collect and normalize intelligence reports."""
        list_items = self.fetch_list(days_back=days_back)
        if not list_items:
            logger.info("[ThreatBook SilverFox] No items in list, exiting")
            return []

        new_uuids = []
        skipped_count = 0
        for item in list_items:
            uuid = item.get("uuid")
            if uuid and uuid not in self.cache:
                new_uuids.append(uuid)
            else:
                skipped_count += 1

        logger.info(
            "[ThreatBook SilverFox] %d new items, %d cached items skipped",
            len(new_uuids), skipped_count,
        )

        if not new_uuids:
            return []

        bulletins = []
        for i, uuid in enumerate(new_uuids):
            if i > 0:
                time.sleep(1)

            detail = self.fetch_detail(uuid)
            if not detail:
                continue

            bulletin = self.normalize(detail)
            if bulletin:
                bulletins.append(bulletin)
                self.cache.add(uuid)

        save_cache(self.cache)

        logger.info("[ThreatBook SilverFox] Collected %d bulletins", len(bulletins))
        return bulletins


# ---------------------------------------------------------------------------
# Push
# ---------------------------------------------------------------------------

def push_to_seclens(bulletins: list[dict]) -> dict:
    """Submit bulletins to the SecLens Ingest API in bounded chunks."""
    endpoint = f"{SECLENS_URL}/v1/ingest/bulletins"
    accepted_total = 0
    duplicates_total = 0
    for offset in range(0, len(bulletins), INGEST_BATCH_SIZE):
        chunk = bulletins[offset : offset + INGEST_BATCH_SIZE]
        logger.info(
            "Pushing chunk %d-%d/%d to %s",
            offset + 1,
            offset + len(chunk),
            len(bulletins),
            endpoint,
        )
        resp = requests.post(
            endpoint,
            json=chunk,
            headers={
                "Authorization": f"Bearer {SECLENS_TOKEN}",
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        result = resp.json()
        accepted_total += int(result.get("accepted", 0))
        duplicates_total += int(result.get("duplicates", 0))
    logger.info(
        "Server response (aggregated): accepted=%s, duplicates=%s",
        accepted_total,
        duplicates_total,
    )
    return {"accepted": accepted_total, "duplicates": duplicates_total}


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

    collector = ThreatBookSilverFoxCollector()
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
