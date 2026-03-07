"""Lenovo Security Advisory Collector (standalone).

Fetches product security advisories from Lenovo's support API and pushes
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

SOURCE_SLUG = "lenovo_security_advisory"
USER_AGENT = "SeclensCollector/2.0 (lenovo_security_advisory)"
REQUEST_TIMEOUT = 30
STATE_FILE_NAME = ".cursor"
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)

API_BASE_URL = "https://newsupport.lenovo.com.cn/api/SafeNotice/SafeNoticeListInfo"
DETAIL_API_URL = "https://iknow.lenovo.com.cn/knowledgeapi/api/knowledge/knowledgeDetails"
DEFAULT_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Content-Type": "application/json",
    "Origin": "https://newsupport.lenovo.com.cn",
    "Referer": "https://newsupport.lenovo.com.cn/SecurityPolicy.html",
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
# Helpers
# ---------------------------------------------------------------------------


def _clean_html_content(html_content: str | None) -> str:
    """Extract clean text from HTML content using BeautifulSoup."""
    if not html_content:
        return ""

    try:
        soup = BeautifulSoup(html_content, "html.parser")

        for script in soup(["script", "style"]):
            script.decompose()

        text = soup.get_text(separator="\n", strip=True)

        lines = [line.strip() for line in text.splitlines()]
        clean_text = '\n'.join(line for line in lines if line)

        return clean_text
    except Exception as e:
        LOGGER.warning(f"Failed to clean HTML content: {e}")
        return html_content


# ---------------------------------------------------------------------------
# Fetch parameters
# ---------------------------------------------------------------------------


@dataclass
class FetchParams:
    """Pagination and filtering settings for the Lenovo API."""

    page_index: int = 1
    page_size: int = 20
    order_way: int = 0  # 0 for descending, 1 for ascending


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class LenovoCollector:
    """Fetch and normalize Lenovo product security advisories."""

    def __init__(
        self,
        session: requests.Session | None = None,
    ) -> None:
        self.session = session or requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    def fetch_list(self, params: FetchParams) -> Sequence[dict]:
        """Fetch the list of security advisories from Lenovo API."""
        response = self.session.get(
            API_BASE_URL,
            params={
                "order_way": params.order_way,
                "page_index": params.page_index,
                "page_size": params.page_size,
            },
            timeout=30,
        )
        response.raise_for_status()
        body = response.json()

        data = body.get("data")
        if isinstance(data, dict):
            items = data.get("data")
            if isinstance(items, list):
                return items

        return []

    def fetch_detail(self, knowledge_no: str) -> dict | None:
        """Fetch detailed information for a specific advisory."""
        try:
            response = self.session.get(
                DETAIL_API_URL,
                params={
                    "knowledgeNo": knowledge_no,
                    "keyWord": knowledge_no,
                    "keyWordId": "",
                },
                timeout=30,
            )
            response.raise_for_status()
            body = response.json()
            if body.get("code") == 200:
                return body.get("data")
        except Exception as e:
            LOGGER.warning(f"Failed to fetch detail for knowledgeNo {knowledge_no}: {e}")

        return None

    def extract_knowledge_no_from_url(self, url: str) -> str | None:
        """Extract knowledge number from the notice_link URL."""
        match = re.search(r'detail/(\d+)', url)
        if match:
            return match.group(1)
        return None

    def normalize(self, item: dict) -> dict:
        """Normalize API response item to a bulletin dict."""
        fetched_at = now_utc_iso()

        notice_link = item.get("notice_link", "")
        knowledge_no = self.extract_knowledge_no_from_url(notice_link)

        detail_data = None
        content_html = ""
        if knowledge_no:
            detail_data = self.fetch_detail(knowledge_no)
            if detail_data:
                content_html = detail_data.get("content", "")

        title = detail_data.get("title", "") if detail_data else ""
        if not title:
            title = item.get("notice_name", "") or item.get("title", "") or ""

        summary = ""
        if detail_data and detail_data.get("digest"):
            summary = detail_data["digest"]
        else:
            summary = item.get("notice_name", "")

        # Parse publication time - Chinese source, use Asia/Shanghai
        published_at = parse_first(
            [
                (item.get("publish_at"), "item.publish_at"),
                (item.get("created_at"), "item.created_at"),
                (item.get("last_at"), "item.last_at"),
            ],
            default_tz="Asia/Shanghai",
        )

        # Fallback to detail API times
        if not published_at and detail_data:
            published_at = parse_first(
                [
                    (detail_data.get("createTime"), "detail.createTime"),
                    (detail_data.get("updateTime"), "detail.updateTime"),
                ],
                default_tz="Asia/Shanghai",
            )

        # Parse CVE IDs
        cve_str = item.get("notice_cves", "")
        cve_ids = []
        if cve_str:
            cve_candidates = re.split(r'[、,，]', cve_str)
            for cve_candidate in cve_candidates:
                cve_candidate = cve_candidate.strip()
                if cve_candidate.upper().startswith('CVE-'):
                    cve_ids.append(cve_candidate.upper())

        # Extract severity from content
        severity = None
        if content_html:
            if "严重性：高" in content_html or "严重性</a>：高" in content_html:
                severity = "high"
            elif "严重性：中" in content_html or "严重性</a>：中" in content_html:
                severity = "medium"
            elif "严重性：低" in content_html or "严重性</a>：低" in content_html:
                severity = "low"

        origin_url = notice_link
        external_id = item.get("notice_number") or item.get("notice_code")
        if external_id is not None:
            external_id = str(external_id).strip() or None

        clean_content = _clean_html_content(content_html)

        labels: list[str] = []
        if item.get("notice_number"):
            labels.append(item["notice_number"])

        topics = ["official_bulletin"]
        if cve_ids:
            topics.append("cve")

        extra: dict[str, object] = {
            "notice_code": item.get("notice_code"),
            "notice_number": item.get("notice_number"),
            "power_level": item.get("power_level"),
            "created_at": item.get("created_at"),
            "last_at": item.get("last_at"),
            "updated_at": item.get("updated_at"),
            "cves_raw": item.get("notice_cves"),
        }

        if detail_data:
            extra.update({
                "knowledge_no": detail_data.get("knowledgeNo"),
                "detail_title": detail_data.get("title"),
                "digest": detail_data.get("digest"),
                "create_time": detail_data.get("createTime"),
                "update_time": detail_data.get("updateTime"),
                "line_category_name": detail_data.get("lineCategoryName"),
                "line_category_names": detail_data.get("lineCategoryNameS"),
                "question_category_name": detail_data.get("questionCategoryName"),
                "first_topic_name": detail_data.get("firstTopicName"),
                "sub_topic_name": detail_data.get("subTopicName"),
                "keywords": detail_data.get("keyWords"),
                "version_no": detail_data.get("versionNo"),
                "html_content": content_html,
            })

        raw = dict(item)
        if detail_data:
            raw["detail"] = detail_data

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
                "body_text": clean_content,
                "published_at": published_at,
                "language": "zh-CN",
            },
            "severity": severity,
            "fetched_at": fetched_at,
            "labels": labels,
            "topics": topics,
            "extra": extra,
            "raw": raw,
        }

    def collect(self, params: FetchParams | None = None) -> list[dict]:
        """Collect and normalize Lenovo security advisories."""
        params = params or FetchParams()
        items = self.fetch_list(params)
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

    collector = LenovoCollector()
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
