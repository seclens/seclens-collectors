"""MIIT CNVDB Vulnerability Alert Collector (standalone).

Collects vulnerability risk alerts published by the MIIT CNVDB platform.

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
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, List

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.time_helpers import parse_first, now_utc_iso

# Import the co-located client module
from cnvdb_client import CNVDBClient

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")

SOURCE_SLUG = "cnvdb"
USER_AGENT = "SeclensCollector/2.0 (cnvdb)"
REQUEST_TIMEOUT = 30
DEFAULT_PAGE_SIZE = 15
DEFAULT_LANGUAGE = "zh"
ORIGIN_URL_TEMPLATE = "https://cnvdb.org.cn/#/policy/detail/{policy_id}"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _html_to_text(html: str | None) -> str | None:
    if not html:
        return None
    soup = BeautifulSoup(html, "html.parser")
    tokens = [segment.strip() for segment in soup.stripped_strings]
    if not tokens:
        return None
    return " ".join(tokens)


def _build_summary(text: str | None, length: int = 280) -> str | None:
    if not text:
        return None
    if len(text) <= length:
        return text
    return text[: length - 1].rstrip() + "..."


@dataclass
class FetchParams:
    page: int = 1
    page_size: int = DEFAULT_PAGE_SIZE


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class CNVDBCollector:
    """Encapsulates fetch and normalisation logic for CNVDB policies."""

    def __init__(self, client: CNVDBClient | None = None) -> None:
        self.client = client or CNVDBClient()
        session = getattr(self.client, "session", None)
        if session is not None and hasattr(session, "headers"):
            session.headers.setdefault("User-Agent", USER_AGENT)

    def fetch_records(self, params: FetchParams) -> list[dict]:
        payload = self.client.list_policies(page=params.page, page_size=params.page_size)
        records = payload.get("data", {}).get("records", [])
        if not isinstance(records, Iterable):
            logger.warning("Unexpected list payload from CNVDB: %s", payload)
            return []
        filtered: list[dict] = []
        for item in records:
            if isinstance(item, dict):
                filtered.append(item)
        return filtered

    def fetch_detail(self, policy_id: str) -> dict | None:
        try:
            payload = self.client.get_policy_detail(policy_id)
        except requests.HTTPError:
            logger.exception("Failed to fetch detail for policy %s", policy_id)
            return None
        data = payload.get("data")
        if isinstance(data, dict):
            return data
        logger.warning("Unexpected detail payload for %s: %s", policy_id, payload)
        return None

    def normalize(self, record: dict, detail: dict | None) -> dict:
        """Normalize record to bulletin dict."""
        fetched_at = now_utc_iso()

        policy_id: str | None = None
        record_id = record.get("id")
        if record_id:
            policy_id = str(record_id)
        elif detail and detail.get("id"):
            policy_id = str(detail.get("id"))

        published_at = parse_first(
            [
                (detail.get("releaseTime") if detail else None, "detail.releaseTime"),
                (detail.get("updateTime") if detail else None, "detail.updateTime"),
                (record.get("releaseTime"), "record.releaseTime"),
            ],
            default_tz="Asia/Shanghai",
        )

        content_html = (detail or {}).get("content")
        body_text = _html_to_text(content_html)
        summary = _build_summary(body_text)
        origin_url = ORIGIN_URL_TEMPLATE.format(policy_id=policy_id) if policy_id else None

        extra: dict[str, object] = {
            "origin": (detail or record).get("origin"),
            "system_type": (detail or record).get("systemType"),
            "release_time_raw": (detail or record).get("releaseTime"),
            "content_html": content_html,
        }
        if detail:
            extra.update(
                {
                    "create_time": detail.get("createTime"),
                    "update_time": detail.get("updateTime"),
                    "click_number": detail.get("clickNumber"),
                    "record_type": detail.get("type"),
                }
            )

        labels: list[str] = []
        if record.get("keyword"):
            labels.append(f"keyword:{record['keyword']}")
        if record.get("systemType") is not None:
            labels.append(f"system_type:{record['systemType']}")

        topics = ["official_bulletin", "vulnerability_warning"]

        return {
            "source": {
                "source_slug": SOURCE_SLUG,
                "external_id": policy_id or None,
                "origin_url": origin_url,
            },
            "content": {
                "title": (detail or {}).get("title") or record.get("title") or "(untitled)",
                "summary": summary,
                "body_text": body_text,
                "published_at": published_at,
                "language": DEFAULT_LANGUAGE,
            },
            "severity": None,
            "fetched_at": fetched_at,
            "labels": labels,
            "topics": topics,
            "extra": extra,
            "raw": {"summary": record, "detail": detail} if detail else {"summary": record},
        }

    def collect(self, params: FetchParams | None = None) -> List[dict]:
        params = params or FetchParams()
        records = self.fetch_records(params)
        bulletins: list[dict] = []
        for record in records:
            policy_id = record.get("id")
            detail = self.fetch_detail(str(policy_id)) if policy_id is not None else None
            bulletin = self.normalize(record, detail)
            bulletins.append(bulletin)
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

    collector = CNVDBCollector()
    bulletins = collector.collect()

    if not bulletins:
        logger.info("No items to push")
        return

    result = push_to_seclens(bulletins)
    print(f"Done: {len(bulletins)} fetched, {result.get('accepted', 0)} accepted, {result.get('duplicates', 0)} duplicates")


if __name__ == "__main__":
    main()
