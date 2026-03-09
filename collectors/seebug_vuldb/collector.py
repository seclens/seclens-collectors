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
    from shared.time_helpers import now_utc_iso
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from shared.manifest import load_manifest_for_slug
    from shared.time_helpers import now_utc_iso

SOURCE_SLUG = "seebug_vuldb"
SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")
BASE_URL = os.environ.get("SEEBUG_VULDB_BASE_URL", "https://www.seebug.org")
LIST_URL = os.environ.get("SEEBUG_VULDB_LIST_URL", "https://www.seebug.org/vuldb/vulnerabilities")
REQUEST_TIMEOUT = 30
USER_AGENT = "SeclensCollector/2.0 (seebug_vuldb)"
LIMIT = int(os.environ.get("SEEBUG_VULDB_LIMIT", "30"))
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(
    SOURCE_SLUG, repo_root=Path(__file__).resolve().parents[2]
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(SOURCE_SLUG)

SSVID_RE = re.compile(r"/vuldb/(ssvid-[0-9]+)")


def _trim(value: str | None) -> str | None:
    if not value:
        return None
    value = " ".join(value.split()).strip()
    return value or None


def fetch_list() -> list[tuple[str, str, str]]:
    resp = requests.get(LIST_URL, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")
    items: list[tuple[str, str, str]] = []
    seen: set[str] = set()

    for a in soup.select('a[href*="/vuldb/ssvid-"]'):
        href = _trim(a.get("href"))
        if not href:
            continue
        m = SSVID_RE.search(href)
        if not m:
            continue
        ssvid = m.group(1)
        if ssvid in seen:
            continue
        seen.add(ssvid)
        title = _trim(a.get_text(" ", strip=True)) or ssvid
        full_url = urljoin(BASE_URL, href)
        items.append((ssvid, title, full_url))
        if len(items) >= LIMIT:
            break

    return items


def fetch_detail(url: str) -> tuple[str | None, str | None]:
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
    except Exception as exc:
        logger.warning("detail fetch failed for %s: %s", url, exc)
        return None, None

    soup = BeautifulSoup(resp.text, "html.parser")
    summary = None
    meta_desc = soup.find("meta", attrs={"name": "description"})
    if meta_desc and meta_desc.get("content"):
        summary = _trim(meta_desc.get("content"))
    if not summary:
        og_desc = soup.find("meta", attrs={"property": "og:description"})
        if og_desc and og_desc.get("content"):
            summary = _trim(og_desc.get("content"))

    body_text = None
    detail_node = soup.select_one(".page-vul-detail-wrapper") or soup.select_one("#j-affix-target")
    if detail_node:
        candidate = _trim(detail_node.get_text("\n", strip=True))
        if candidate and "登录后查看" not in candidate:
            body_text = candidate

    return summary, body_text


def normalize(ssvid: str, title: str, origin_url: str, summary: str | None, body_text: str | None) -> dict:
    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": ssvid,
            "origin_url": origin_url,
            "manifest": MANIFEST,
            "manifest_hash": MANIFEST_HASH,
            "manifest_version": MANIFEST_VERSION,
        },
        "content": {
            "title": title,
            "summary": summary,
            "body_text": body_text,
            "published_at": None,
            "language": "zh",
        },
        "fetched_at": now_utc_iso(),
        "labels": ["source:seebug", "type:vuln"],
        "topics": ["vulnerability", "security-advisory"],
        "extra": {"ssvid": ssvid},
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

    items = fetch_list()
    logger.info("Fetched %d entries from Seebug list", len(items))

    bulletins = []
    for ssvid, title, url in items:
        summary, body_text = fetch_detail(url)
        bulletins.append(normalize(ssvid, title, url, summary, body_text))

    if not bulletins:
        logger.info("No bulletins to push")
        return

    result = push(bulletins)
    logger.info("Push done: accepted=%s duplicates=%s", result.get("accepted"), result.get("duplicates"))


if __name__ == "__main__":
    main()
