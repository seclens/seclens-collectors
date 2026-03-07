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
RSS_URL = os.environ.get("SEEBUG_PAPER_RSS_URL", "https://paper.seebug.org/rss/")
REQUEST_TIMEOUT = 30
USER_AGENT = "SeclensCollector/2.0 (seebug_paper_rss)"
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(
    SOURCE_SLUG, repo_root=Path(__file__).resolve().parents[2]
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(SOURCE_SLUG)


def _trim(v: str | None) -> str | None:
    if not v:
        return None
    v = " ".join(v.split()).strip()
    return v or None


def fetch_items() -> list[ET.Element]:
    resp = requests.get(
        RSS_URL,
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/xml"},
    )
    resp.raise_for_status()
    root = ET.fromstring(resp.content)
    channel = root.find("channel")
    return channel.findall("item") if channel is not None else root.findall(".//item")


def normalize(item: ET.Element) -> dict:
    title = _trim(item.findtext("title")) or "(untitled)"
    link = _trim(item.findtext("link"))
    description = _trim(item.findtext("description"))
    guid = _trim(item.findtext("guid"))
    pub = parse_datetime(item.findtext("pubDate"))
    external_id = guid or link or title

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": external_id,
            "origin_url": link,
            "manifest": MANIFEST,
            "manifest_hash": MANIFEST_HASH,
            "manifest_version": MANIFEST_VERSION,
        },
        "content": {
            "title": title,
            "summary": description,
            "published_at": pub,
            "language": "zh",
        },
        "fetched_at": now_utc_iso(),
        "labels": ["source:seebug", "type:paper"],
        "topics": ["security-research", "paper"],
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
    logger.info("Fetched %d items from Seebug paper RSS", len(items))
    bulletins = [normalize(i) for i in items]
    if not bulletins:
        logger.info("No bulletins to push")
        return

    result = push(bulletins)
    logger.info("Push done: accepted=%s duplicates=%s", result.get("accepted"), result.get("duplicates"))


if __name__ == "__main__":
    main()
