"""Huawei Security Advisory Collector (standalone).

Fetches enterprise security advisories from Huawei's public API and pushes
them to a SecLens server.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 6 hours (21600s)
"""
from __future__ import annotations

import logging
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

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

SOURCE_SLUG = "huawei_security"
USER_AGENT = "SeclensCollector/2.0 (huawei_security)"
REQUEST_TIMEOUT = 30
STATE_FILE_NAME = ".cursor"
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)

API_URL = "https://securitybulletin.huawei.com/vdmsapi/services/vdmsapi/rest/v1/enterprise/advisories"
DEFAULT_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "Content-Type": "application/json",
    "Origin": "https://securitybulletin.huawei.com",
    "Referer": "https://securitybulletin.huawei.com/enterprise/en/security-advisory",
    "User-Agent": USER_AGENT,
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
LOGGER = logging.getLogger(SOURCE_SLUG)


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
# Fetch parameters
# ---------------------------------------------------------------------------


@dataclass
class FetchParams:
    page_index: int = 1
    page_size: int = 20
    sort: int = 1
    sort_field: str = "publish_date"
    keyword: str = ""
    publish_date_from: str = ""
    publish_date_to: str = ""
    product_line: str = ""
    range: int = 1


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class HuaweiCollector:
    """Fetch and normalize Huawei enterprise security advisories."""

    def __init__(
        self,
        session: requests.Session | None = None,
    ) -> None:
        self.session = session or requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    def fetch(self, params: FetchParams) -> Sequence[dict]:
        payload = {
            "keyword": params.keyword,
            "publishDateFrom": params.publish_date_from,
            "publishDateTo": params.publish_date_to,
            "products": [],
            "sort": params.sort,
            "sortField": params.sort_field,
            "vulId": "",
            "cveId": "",
            "cvssFrom": None,
            "cvssTo": None,
            "severity": [],
            "productVersionsMsg": [],
            "productLine": params.product_line,
            "range": params.range,
        }
        query = {"pageIndex": params.page_index, "pageSize": params.page_size}
        response = self.session.post(API_URL, params=query, json=payload, timeout=30)
        response.raise_for_status()
        body = response.json()
        data = body.get("data")
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            records = (
                data.get("records")
                or data.get("rows")
                or data.get("list")
                or data.get("data")
            )
            if isinstance(records, list):
                return records
        return []

    def normalize(self, item: dict) -> dict:
        title = (
            item.get("advisoryTitle")
            or item.get("title")
            or item.get("name")
            or item.get("sasnTitle")
            or ""
        )
        origin_url = item.get("advisoryUrl") or item.get("url") or item.get("allPath")
        summary = item.get("summary") or item.get("overview") or item.get("description")
        body_text = item.get("content") or item.get("details") or summary
        fetched_at = now_utc_iso()

        published_at = parse_first(
            [
                (item.get("publishTime"), "item.publishTime"),
                (item.get("pubTime"), "item.pubTime"),
                (item.get("publishDate"), "item.publishDate"),
                (item.get("releaseTime"), "item.releaseTime"),
                (item.get("releaseDate"), "item.releaseDate"),
            ],
            default_tz="UTC",
        )

        severity = item.get("severity") or item.get("level")
        labels: list[str] = []
        advisory_type = item.get("advisoryType") or item.get("type")
        if advisory_type:
            labels.append(str(advisory_type))
        topics = ["official_bulletin"]
        cve_ids = item.get("cveIds") or item.get("cveList")
        if not cve_ids and isinstance(item.get("vul"), list):
            cve_ids = [entry.get("cveId") for entry in item["vul"] if entry.get("cveId")]
        if isinstance(cve_ids, str):
            cve_ids = [c.strip() for c in cve_ids.split(",") if c.strip()]
        if not isinstance(cve_ids, list):
            cve_ids = []

        external_id = (
            item.get("advisoryNo")
            or item.get("id")
            or item.get("docId")
            or item.get("sasnNo")
        )
        if external_id is not None:
            external_id = str(external_id).strip() or None

        normalized_labels = [label for label in labels if label]
        if cve_ids:
            topics.append("cve")
        if severity:
            normalized_labels.append(str(severity))

        extra: dict[str, object] = {
            "sasn_no": item.get("sasnNo"),
            "sasn_version": item.get("sasnVersion"),
            "severity": severity,
            "language": item.get("lang") or item.get("language"),
        }
        hw_ids = [entry.get("hwPsirtId") for entry in item.get("vul", []) if isinstance(entry, dict) and entry.get("hwPsirtId")]
        if hw_ids:
            extra["hw_psirt_ids"] = hw_ids
        if item.get("vul"):
            extra["vulnerabilities"] = item.get("vul")

        raw = dict(item)
        if cve_ids:
            raw.setdefault("cveIds", cve_ids)

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
                "title": title,
                "summary": summary,
                "body_text": body_text,
                "published_at": published_at,
                "language": item.get("lang") or item.get("language") or "en",
            },
            "severity": str(severity) if severity else None,
            "fetched_at": fetched_at,
            "labels": normalized_labels,
            "topics": topics,
            "extra": extra,
            "raw": raw,
        }

    def collect(self, params: FetchParams | None = None) -> list[dict]:
        params = params or FetchParams()
        items = self.fetch(params)
        return [self.normalize(item) for item in items]


# ---------------------------------------------------------------------------
# Push
# ---------------------------------------------------------------------------


def push_to_seclens(bulletins: list[dict]) -> dict:
    """Submit bulletins to the SecLens Ingest API."""
    endpoint = f"{SECLENS_URL}/v1/ingest/bulletins"
    LOGGER.info("Pushing %d bulletins to %s", len(bulletins), endpoint)

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
    LOGGER.info(
        "Server response: accepted=%s, duplicates=%s",
        result.get("accepted"),
        result.get("duplicates"),
    )
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    if not SECLENS_URL:
        LOGGER.error("SECLENS_URL environment variable is required")
        sys.exit(1)
    if not SECLENS_TOKEN:
        LOGGER.error("SECLENS_TOKEN environment variable is required")
        sys.exit(1)

    collector = HuaweiCollector()
    bulletins = collector.collect()
    latest_cursor = None
    if bulletins:
        latest_cursor = bulletins[0].get("source", {}).get("external_id")
    previous_cursor = load_cursor()
    if previous_cursor:
        filtered: list[dict] = []
        for bulletin in bulletins:
            current = str(bulletin.get("source", {}).get("external_id") or "")
            if current == previous_cursor:
                break
            filtered.append(bulletin)
        bulletins = filtered
        LOGGER.info(
            "Cursor check: previous=%s, pending=%d",
            previous_cursor,
            len(bulletins),
        )

    if not bulletins:
        LOGGER.info("No bulletins to push")
        return

    result = push_to_seclens(bulletins)
    if latest_cursor:
        save_cursor(str(latest_cursor))
    LOGGER.info(
        "Done: fetched=%d accepted=%s duplicates=%s",
        len(bulletins),
        result.get("accepted", 0),
        result.get("duplicates", 0),
    )


if __name__ == "__main__":
    main()
