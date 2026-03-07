"""Tencent Cloud Security Announcement Collector (standalone).

Fetches security announcements from Tencent Cloud's announcement page
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
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from html import unescape
from html.parser import HTMLParser
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

SOURCE_SLUG = "tencent_cloud_security"
USER_AGENT = "SeclensCollector/2.0 (tencent_cloud_security)"
REQUEST_TIMEOUT = 30
DEFAULT_LIST_URL = "https://cloud.tencent.com/announce/?categorys=21"
DETAIL_URL_TEMPLATE = "https://cloud.tencent.com/announce/detail/{announce_id}"
DEFAULT_LIMIT = 20
STATE_FILE_NAME = ".cursor"
CHINA_TZ = timezone(timedelta(hours=8))
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
LOGGER = logging.getLogger(SOURCE_SLUG)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

ASYNC_DATA_PATTERN = re.compile(r"window\['__ASYNC_DATA__'\]\s*=\s*(\[[\s\S]*\])", re.MULTILINE)


@dataclass
class AnnouncementSummary:
    announce_id: str
    title: str
    begin_time: datetime
    end_time: datetime | None
    add_time: datetime | None
    is_important: bool
    announce_type: str | None


@dataclass
class AnnouncementDetail:
    summary: AnnouncementSummary
    content_html: str | None


class _HTMLStripper(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._buffer: list[str] = []

    def handle_data(self, data: str) -> None:
        if data.strip():
            self._buffer.append(data.strip())

    def get_text(self) -> str | None:
        if not self._buffer:
            return None
        return " ".join(self._buffer)


def _clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    return " ".join(value.split()).strip() or None


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        dt = dt.replace(tzinfo=CHINA_TZ)
        return dt.astimezone(UTC)
    except ValueError:
        LOGGER.warning("Failed to parse datetime '%s'", value)
        return None


def _html_to_text(html_content: str | None) -> str | None:
    if not html_content:
        return None
    stripped = unescape(html_content)
    parser = _HTMLStripper()
    parser.feed(stripped)
    return _clean_text(parser.get_text())


def _extract_async_payload(html: str) -> list:
    match = ASYNC_DATA_PATTERN.search(html)
    if match:
        payload_raw = match.group(1)
    else:
        marker = "window['__ASYNC_DATA__']"
        idx = html.find(marker)
        if idx == -1:
            raise ValueError("Async payload not found in response")
        eq_idx = html.find('=', idx)
        if eq_idx == -1:
            raise ValueError("Async payload not found in response")
        snippet = html[eq_idx + 1:]
        end_idx = snippet.find('</script>')
        if end_idx != -1:
            snippet = snippet[:end_idx]
        payload_raw = snippet.strip()
    if payload_raw.endswith(';'):
        payload_raw = payload_raw[:-1].strip()
    try:
        return json.loads(payload_raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Failed to decode async payload") from exc


def _iter_containers(data: list) -> Iterable[dict]:
    for item in data:
        if isinstance(item, dict):
            for value in item.values():
                if isinstance(value, list):
                    for element in value:
                        if isinstance(element, dict):
                            yield element


def _parse_announcements(html: str) -> list[AnnouncementSummary]:
    payload = _extract_async_payload(html)
    summaries: list[AnnouncementSummary] = []
    for container in _iter_containers(payload):
        announcements = container.get("announcements")
        if not isinstance(announcements, list):
            continue
        for item in announcements:
            if not isinstance(item, dict):
                continue
            announce_id = str(item.get("announceId"))
            if not announce_id:
                continue
            title = _clean_text(item.get("title")) or announce_id
            begin_time = _parse_datetime(item.get("beginTime"))
            if begin_time is None:
                begin_time = datetime.now(UTC)
            end_time = _parse_datetime(item.get("endTime"))
            add_time = _parse_datetime(item.get("addTime"))
            is_important = str(item.get("isImportant", "0")) == "1"
            announce_type = _clean_text(item.get("type"))
            summaries.append(
                AnnouncementSummary(
                    announce_id=announce_id,
                    title=title,
                    begin_time=begin_time,
                    end_time=end_time,
                    add_time=add_time,
                    is_important=is_important,
                    announce_type=announce_type,
                )
            )
    summaries.sort(key=lambda entry: entry.begin_time)
    return summaries


def _parse_detail(html: str, summary: AnnouncementSummary) -> AnnouncementDetail:
    payload = _extract_async_payload(html)
    content_html: str | None = None
    for container in _iter_containers(payload):
        detail = container.get("detail")
        if isinstance(detail, dict) and str(detail.get("announceId")) == summary.announce_id:
            raw_content = detail.get("content")
            if isinstance(raw_content, str):
                content_html = raw_content
            break
    return AnnouncementDetail(summary=summary, content_html=content_html)


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class TencentCloudCollector:
    """Encapsulates fetch, normalize, and cursor persistence for Tencent Cloud announcements."""

    def __init__(
        self,
        *,
        session: requests.Session | None = None,
        list_url: str | None = None,
        state_path: Path | None = None,
    ) -> None:
        self.session = session or requests.Session()
        self.list_url = list_url or DEFAULT_LIST_URL
        self.state_path = state_path or Path(__file__).resolve().with_name(STATE_FILE_NAME)
        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )

    # --- Cursor helpers -------------------------------------------------
    def load_cursor(self) -> datetime | None:
        try:
            raw = self.state_path.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            return None
        if not raw:
            return None
        try:
            dt = datetime.fromisoformat(raw)
        except ValueError:
            LOGGER.warning("Invalid cursor value '%s'; ignoring", raw)
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)

    def save_cursor(self, value: datetime) -> None:
        value = value.astimezone(UTC)
        self.state_path.write_text(value.isoformat(), encoding="utf-8")

    # --- Fetch ----------------------------------------------------------
    def fetch_summaries(self) -> Sequence[AnnouncementSummary]:
        response = self.session.get(self.list_url, timeout=30)
        response.raise_for_status()
        html = response.text
        summaries = _parse_announcements(html)
        return summaries

    def fetch_detail(self, summary: AnnouncementSummary) -> AnnouncementDetail:
        detail_url = DETAIL_URL_TEMPLATE.format(announce_id=summary.announce_id)
        response = self.session.get(detail_url, timeout=30)
        response.raise_for_status()
        html = response.text
        return _parse_detail(html, summary)

    # --- Normalize ------------------------------------------------------
    def normalize(self, detail: AnnouncementDetail) -> dict:
        summary = detail.summary
        content_html = detail.content_html
        body_text = _html_to_text(content_html)
        origin_url = DETAIL_URL_TEMPLATE.format(announce_id=summary.announce_id)

        fetched_at = now_utc_iso()
        published_at = parse_first(
            [
                (summary.begin_time, "summary.begin_time"),
                (summary.add_time, "summary.add_time"),
            ],
            default_tz="Asia/Shanghai",
        )

        labels: list[str] = []
        if summary.is_important:
            labels.append("important")
        if summary.announce_type:
            labels.append(f"type:{summary.announce_type}")

        topics = ["official_bulletin", "cloud_security"]

        extra: dict[str, object] = {
            "begin_time": summary.begin_time.isoformat(),
        }
        if summary.end_time:
            extra["end_time"] = summary.end_time.isoformat()
        if summary.add_time:
            extra["add_time"] = summary.add_time.isoformat()
        extra["is_important"] = summary.is_important
        if summary.announce_type:
            extra["announce_type"] = summary.announce_type
        if content_html:
            extra["content_html"] = unescape(content_html)

        return {
            "source": {
                "source_slug": SOURCE_SLUG,
                "external_id": summary.announce_id,
                "origin_url": origin_url,
                "manifest": MANIFEST,
                "manifest_hash": MANIFEST_HASH,
                "manifest_version": MANIFEST_VERSION,
            },
            "content": {
                "title": summary.title,
                "summary": body_text or summary.title,
                "body_text": body_text,
                "published_at": published_at,
                "language": "zh",
            },
            "severity": None,
            "fetched_at": fetched_at,
            "labels": labels,
            "topics": topics,
            "extra": extra,
            "raw": {
                "summary": {
                    "announce_id": summary.announce_id,
                    "title": summary.title,
                },
                "detail_html": content_html,
            },
        }

    # --- Collection -----------------------------------------------------
    def collect(self, *, limit: int | None = None, force: bool = False) -> list[dict]:
        limit = limit or DEFAULT_LIMIT
        cursor = None if force else self.load_cursor()
        summaries = list(self.fetch_summaries())

        selected: list[AnnouncementSummary] = []
        for summary in summaries:
            if cursor and summary.begin_time <= cursor:
                continue
            selected.append(summary)
        if limit is not None and limit > 0:
            selected = selected[-limit:]

        bulletins: list[dict] = []
        latest = cursor
        for summary in selected:
            detail = self.fetch_detail(summary)
            bulletin = self.normalize(detail)
            bulletins.append(bulletin)
            if latest is None or summary.begin_time > latest:
                latest = summary.begin_time

        if latest and not force and bulletins:
            self.save_cursor(latest)
        return bulletins


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

    collector = TencentCloudCollector()
    bulletins = collector.collect()

    if not bulletins:
        LOGGER.info("No new bulletins to push")
        return

    result = push_to_seclens(bulletins)
    LOGGER.info(
        "Done: %d fetched, %d accepted, %d duplicates",
        len(bulletins),
        result.get("accepted", 0),
        result.get("duplicates", 0),
    )


if __name__ == "__main__":
    main()
