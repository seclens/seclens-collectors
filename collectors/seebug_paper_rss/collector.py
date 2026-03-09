from __future__ import annotations

import logging
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import requests

try:
    from shared.manifest import load_manifest_for_slug
    from shared.time_helpers import now_utc_iso, parse_datetime
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from shared.manifest import load_manifest_for_slug
    from shared.time_helpers import now_utc_iso, parse_datetime

SOURCE_SLUG = "seebug_paper_rss"
SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")
FEED_URL = os.environ.get("SEEBUG_PAPER_RSS_URL", "https://paper.seebug.org/rss/")
REQUEST_TIMEOUT = 30
USER_AGENT = "SeclensCollector/2.0 (seebug_paper_rss)"
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(
    SOURCE_SLUG, repo_root=Path(__file__).resolve().parents[2]
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(SOURCE_SLUG)


def _trim(value: str | None) -> str | None:
    if not value:
        return None
    value = " ".join(value.split()).strip()
    return value or None


def fetch_items() -> list[ET.Element]:
    resp = requests.get(FEED_URL, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    root = ET.fromstring(resp.content)
    channel = root.find("channel")
    return channel.findall("item") if channel is not None else root.findall(".//item")


def fetch_detail_body(url: str | None) -> str | None:
    if not url:
        return None
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
    except Exception as exc:
        logger.warning("detail fetch failed for %s: %s", url, exc)
        return None

    # Some targets anti-bot with tiny placeholder pages.
    if len(resp.text or "") < 1500:
        return None

    body = None
    # Prefer semantic article area; fallback to largest readable block.
    import re

    body_html = None
    m = re.search(r'<article[^>]*>(.*?)</article>', resp.text, flags=re.I | re.S)
    if m:
        body_html = m.group(1)
    if body_html:
        # conservative html-strip
        text = re.sub(r"<[^>]+>", " ", body_html)
        body = _trim(" ".join(text.split()))

    return body


def normalize(item: ET.Element, body_text: str | None = None) -> dict:
    title = _trim(item.findtext("title")) or "(untitled)"
    link = _trim(item.findtext("link"))
    guid = _trim(item.findtext("guid"))
    description = _trim(item.findtext("description"))
    pub_date = parse_datetime(item.findtext("pubDate"))

    ext = guid or link or title
    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": ext,
            "origin_url": link,
            "manifest": MANIFEST,
            "manifest_hash": MANIFEST_HASH,
            "manifest_version": MANIFEST_VERSION,
        },
        "content": {
            "title": title,
            "summary": description,
            "body_text": body_text,
            "published_at": pub_date,
            "language": "zh",
        },
        "fetched_at": now_utc_iso(),
        "labels": ["source:seebug", "type:paper"],
        "topics": ["security-research", "threat-intel"],
        "extra": {"guid": guid},
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

    items = fetch_items()
    bulletins = []
    for i in items:
        link = _trim(i.findtext("link"))
        body_text = fetch_detail_body(link)
        bulletins.append(normalize(i, body_text=body_text))
    logger.info("Fetched %d items from Seebug Paper RSS", len(bulletins))
    if not bulletins:
        return

    result = push(bulletins)
    logger.info("Push done: accepted=%s duplicates=%s", result.get("accepted"), result.get("duplicates"))


if __name__ == "__main__":
    main()
