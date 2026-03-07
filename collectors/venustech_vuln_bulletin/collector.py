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
LIST_URL = os.environ.get("VENUSTECH_AQTG_URL", "https://www.venustech.com.cn/new_type/aqtg/")
BASE_URL = os.environ.get("VENUSTECH_BASE_URL", "https://www.venustech.com.cn")
REQUEST_TIMEOUT = 30
LIMIT = int(os.environ.get("VENUSTECH_AQTG_LIMIT", "30"))
USER_AGENT = "SeclensCollector/2.0 (venustech_vuln_bulletin)"
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(
    SOURCE_SLUG, repo_root=Path(__file__).resolve().parents[2]
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(SOURCE_SLUG)

ID_RE = re.compile(r"/new_type/aqtg/([0-9]{8}/[0-9]+\.html)")
DATE_RE = re.compile(r"/new_type/aqtg/([0-9]{8})/")


def _trim(v: str | None) -> str | None:
    if not v:
        return None
    v = " ".join(v.split()).strip()
    return v or None


def fetch_list() -> list[tuple[str, str, str, str | None]]:
    resp = requests.get(LIST_URL, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")

    seen: set[str] = set()
    out: list[tuple[str, str, str, str | None]] = []

    for a in soup.select('a[href*="/new_type/aqtg/"][href$=".html"]'):
        href = _trim(a.get("href"))
        if not href:
            continue
        m = ID_RE.search(href)
        if not m:
            continue
        external_id = m.group(1)
        if external_id in seen:
            continue
        seen.add(external_id)

        title = _trim(a.get_text(" ", strip=True)) or external_id
        full_url = urljoin(BASE_URL, href)
        dm = DATE_RE.search(href)
        pub = None
        if dm:
            d = dm.group(1)
            pub = parse_datetime(f"{d[:4]}-{d[4:6]}-{d[6:8]}T00:00:00+08:00")

        out.append((external_id, title, full_url, pub))
        if len(out) >= LIMIT:
            break

    return out


def fetch_detail_summary(url: str) -> str | None:
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
    except Exception as exc:
        logger.warning("detail fetch failed for %s: %s", url, exc)
        return None

    soup = BeautifulSoup(resp.text, "html.parser")
    meta_desc = soup.find("meta", attrs={"name": "description"})
    if meta_desc and meta_desc.get("content"):
        return _trim(meta_desc.get("content"))

    text_node = soup.select_one(".news_text")
    if text_node:
        return _trim(text_node.get_text(" ", strip=True))
    return None


def normalize(external_id: str, title: str, origin_url: str, published_at: str | None, summary: str | None) -> dict:
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
        "topics": ["vulnerability", "security-advisory", "vendor-alert"],
        "extra": {"bulletin_id": external_id},
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
    logger.info("Fetched %d entries from Venustech list", len(rows))

    bulletins = []
    for external_id, title, url, published_at in rows:
        summary = fetch_detail_summary(url)
        bulletins.append(normalize(external_id, title, url, published_at, summary))

    if not bulletins:
        logger.info("No bulletins to push")
        return

    result = push(bulletins)
    logger.info("Push done: accepted=%s duplicates=%s", result.get("accepted"), result.get("duplicates"))


if __name__ == "__main__":
    main()
