from __future__ import annotations

import logging
import os
import re
import sys
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

try:
    from shared.manifest import load_manifest_for_slug
    from shared.time_helpers import now_utc_iso, parse_datetime
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from shared.manifest import load_manifest_for_slug
    from shared.time_helpers import now_utc_iso, parse_datetime

SOURCE_SLUG = "venustech_vuln_bulletin"
SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")
LIST_URL = os.environ.get("VENUSTECH_VULN_LIST_URL", "https://www.venustech.com.cn/new_type/aqtg/")
BASE_URL = "https://www.venustech.com.cn"
REQUEST_TIMEOUT = 30
USER_AGENT = "SeclensCollector/2.0 (venustech_vuln_bulletin)"
LIMIT = int(os.environ.get("VENUSTECH_VULN_LIMIT", "30"))
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(
    SOURCE_SLUG, repo_root=Path(__file__).resolve().parents[2]
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(SOURCE_SLUG)

DETAIL_RE = re.compile(r"/new_type/aqtg/\d{8}/\d+\.html")
DATE_RE = re.compile(r"(20\d{2}-\d{2}-\d{2}|20\d{6})")


def _trim(value: str | None) -> str | None:
    if not value:
        return None
    value = " ".join(value.split()).strip()
    return value or None


def fetch_list() -> list[tuple[str, str]]:
    resp = requests.get(LIST_URL, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")

    rows: list[tuple[str, str]] = []
    seen: set[str] = set()
    for a in soup.select('a[href*="/new_type/aqtg/"]'):
        href = _trim(a.get("href"))
        if not href or not DETAIL_RE.search(href):
            continue
        full = urljoin(BASE_URL, href)
        if full in seen:
            continue
        seen.add(full)
        title = _trim(a.get_text(" ", strip=True)) or "(untitled)"
        rows.append((full, title))
        if len(rows) >= LIMIT:
            break
    return rows


def fetch_detail(url: str) -> tuple[str | None, str | None]:
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
    except Exception as exc:
        logger.warning("detail fetch failed for %s: %s", url, exc)
        return None, None

    soup = BeautifulSoup(resp.text, "html.parser")
    desc = None
    meta = soup.find("meta", attrs={"name": "description"})
    if meta and meta.get("content"):
        desc = _trim(meta.get("content"))

    text = soup.get_text(" ", strip=True)
    m = DATE_RE.search(text)
    published_at = None
    if m:
        raw = m.group(1)
        if len(raw) == 8 and raw.isdigit():
            raw = f"{raw[0:4]}-{raw[4:6]}-{raw[6:8]}"
        published_at = parse_datetime(raw + " 00:00:00", default_tz="Asia/Shanghai")
    return desc, published_at


def normalize(origin_url: str, title: str, summary: str | None, published_at: str | None) -> dict:
    external_id = origin_url.rsplit("/", 1)[-1].replace(".html", "")
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
            "published_at": published_at,
            "language": "zh",
        },
        "fetched_at": now_utc_iso(),
        "labels": ["source:venustech", "type:vuln-bulletin"],
        "topics": ["vulnerability", "vendor-advisory"],
        "extra": {},
    }


def push(bulletins: list[dict]) -> dict:
    endpoint = f"{SECLENS_URL}/v1/ingest/bulletins"
    resp = requests.post(
        endpoint,
        json=bulletins,
        timeout=REQUEST_TIMEOUT,
        headers={
            "Authorization": f"Bearer {SECLENS_TOKEN}",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    resp.raise_for_status()
    return resp.json()


def main() -> None:
    if not SECLENS_URL or not SECLENS_TOKEN:
        raise SystemExit("SECLENS_URL and SECLENS_TOKEN are required")

    rows = fetch_list()
    logger.info("Fetched %d list entries", len(rows))
    bulletins = []
    for url, title in rows:
        summary, published_at = fetch_detail(url)
        bulletins.append(normalize(url, title, summary, published_at))

    if not bulletins:
        return
    result = push(bulletins)
    logger.info("Push done: accepted=%s duplicates=%s", result.get("accepted"), result.get("duplicates"))


if __name__ == "__main__":
    main()
