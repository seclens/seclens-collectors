"""Alibaba Cloud Linux Security Advisories RSS collector.

Fetches security advisories (errata) from Alibaba Cloud Linux Advisory
System (ALAS) and pushes them to a SecLens server. Fully standalone - no
SecLens app dependencies.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 2 hours (7200s)
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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
SOURCE_SLUG = "alibaba_cloud_linux_advisory"
USER_AGENT = "SeclensCollector/2.0 (alibaba_cloud_linux_advisory)"
DEFAULT_FEED_URL = os.environ.get(
    "ALAS_ADVISORY_FEED_URL",
    "https://alas.aliyuncs.com/api/rss/v1/errata/rss.xml",
)
DETAIL_API_URL = "https://alas.aliyuncs.com/api/portal/v1/errata/errata/{advisory_id}/"
REQUEST_TIMEOUT = 30
CACHE_FILE_NAME = ".cursor"
DEFAULT_LIMIT = 30
MAX_CACHE_SIZE = 200
MAX_RSS_ITEMS = 100
MAX_AGE_DAYS = 30
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)

# Advisory ID pattern (ALINUX3-SA-2025:0164)
ADVISORY_PATTERN = re.compile(r"ALINUX\d+-[A-Z]+-\d{4}:\d+", re.IGNORECASE)
# CVE ID pattern
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@dataclass
class FeedEntry:
    advisory_id: str
    title: str
    link: str
    description: str | None
    cve_ids: list[str]
    published_at: str | None  # ISO 8601 string
    fetched_at: str  # ISO 8601 string
    raw_pub_date: str | None
    # Detail API fields
    affected_products: list[str] | None = None
    solution: str | None = None
    severity: str | None = None
    full_description: str | None = None


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _cache_path() -> Path:
    return Path(__file__).resolve().with_name(CACHE_FILE_NAME)


def load_cache() -> set[str]:
    """Load cached Advisory IDs from JSON file."""
    try:
        with _cache_path().open("r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                items = data.get("advisory_ids", [])
                if isinstance(items, list):
                    return set(items)
        return set()
    except (FileNotFoundError, json.JSONDecodeError):
        return set()


def save_cache(advisory_ids: set[str]) -> None:
    """Save Advisory IDs to cache, keeping only the latest MAX_CACHE_SIZE items."""
    ids_list = list(advisory_ids)[-MAX_CACHE_SIZE:]
    with _cache_path().open("w", encoding="utf-8") as f:
        json.dump(
            {
                "advisory_ids": ids_list,
                "updated_at": now_utc_iso(),
            },
            f,
            indent=2,
        )


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

def fetch_feed(feed_url: str = DEFAULT_FEED_URL) -> Sequence[FeedEntry]:
    """Fetch and parse the ALAS Advisory RSS feed."""
    logger.info("Fetching feed: %s", feed_url)
    response = requests.get(
        feed_url,
        timeout=REQUEST_TIMEOUT,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/rss+xml, application/xml;q=0.9, */*;q=0.8",
        },
    )
    response.raise_for_status()

    try:
        root = ET.fromstring(response.text)
    except ET.ParseError as exc:
        raise ValueError("Failed to parse ALAS Advisory RSS feed") from exc

    entries: list[FeedEntry] = []
    fetched_at = now_utc_iso()
    fetched_dt = datetime.now(timezone.utc)  # noqa: UP017
    cutoff_date = fetched_dt - timedelta(days=MAX_AGE_DAYS)

    items = root.findall(".//item")[:MAX_RSS_ITEMS]
    logger.info("Processing %d RSS items (max: %d)", len(items), MAX_RSS_ITEMS)

    for item in items:
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        if not link or not title:
            continue

        # Extract Advisory ID from title
        advisory_match = ADVISORY_PATTERN.search(title)
        if not advisory_match:
            logger.warning("No Advisory ID found in title: %s", title)
            continue
        advisory_id = advisory_match.group(0).upper()

        desc_node = item.findtext("description")
        description = desc_node.strip() if desc_node else None

        # Extract CVE IDs from description
        cve_ids = []
        if description:
            cve_matches = CVE_PATTERN.findall(description)
            cve_ids = sorted(set(match.upper() for match in cve_matches))

        raw_pub_date = item.findtext("pubDate")
        published_at = parse_first(
            [(raw_pub_date, "item.pubDate")],
            default_tz="Asia/Shanghai",
        )

        # Filter old entries
        if published_at:
            try:
                pub_dt = datetime.fromisoformat(published_at)
                if pub_dt < cutoff_date:
                    logger.debug("Skipping old entry %s: %s", advisory_id, published_at)
                    continue
            except ValueError:
                pass

        entries.append(
            FeedEntry(
                advisory_id=advisory_id,
                title=title,
                link=link,
                description=description,
                cve_ids=cve_ids,
                published_at=published_at,
                fetched_at=fetched_at,
                raw_pub_date=raw_pub_date.strip() if isinstance(raw_pub_date, str) else None,
            )
        )

    logger.info("Fetched %d valid entries within %d days", len(entries), MAX_AGE_DAYS)
    return entries


def fetch_detail(advisory_id: str) -> dict | None:
    """Fetch detailed information from API."""
    url = DETAIL_API_URL.format(advisory_id=advisory_id)
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        response.raise_for_status()
        data = response.json()

        if data.get("status", {}).get("code") == 200:
            return data.get("data")
        else:
            logger.warning("API returned non-200 status for %s", advisory_id)
            return None
    except Exception as e:
        logger.error("Failed to fetch detail for %s: %s", advisory_id, e)
        return None


def enrich_entry(entry: FeedEntry) -> FeedEntry:
    """Enrich entry with details from API."""
    detail = fetch_detail(entry.advisory_id)
    if not detail:
        return entry

    # Extract affected products
    products = detail.get("product", [])
    affected_products = [p.get("name_version") for p in products if p.get("name_version")]

    # Get solution, severity, and full description
    solution = detail.get("solution")
    severity = detail.get("severity")
    full_description = detail.get("description")

    return FeedEntry(
        advisory_id=entry.advisory_id,
        title=entry.title,
        link=entry.link,
        description=entry.description,
        cve_ids=entry.cve_ids,
        published_at=entry.published_at,
        fetched_at=entry.fetched_at,
        raw_pub_date=entry.raw_pub_date,
        affected_products=affected_products if affected_products else None,
        solution=solution,
        severity=severity,
        full_description=full_description,
    )


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------

def normalize(entry: FeedEntry) -> dict:
    """Convert a FeedEntry to a SecLens bulletin dict."""
    # Use full description if available, otherwise use RSS description
    body_text = entry.full_description or entry.description

    # Build summary from solution and affected products
    summary_parts = []
    if entry.description:
        summary_parts.append(entry.description)
    if entry.solution:
        summary_parts.append(f"\n\n**Solution**: {entry.solution}")
    if entry.affected_products:
        summary_parts.append(f"\n\n**Affected Products**: {', '.join(entry.affected_products)}")

    summary = "\n".join(summary_parts) if summary_parts else entry.description

    labels = ["vendor:alibaba", "type:advisory"]
    for cve in entry.cve_ids:
        labels.append(f"cve:{cve.lower()}")

    topics = ["vendor-update", "official_advisory"]
    if entry.cve_ids:
        topics.append("cve")

    extra: dict[str, object] = {
        "advisory_id": entry.advisory_id,
    }
    if entry.cve_ids:
        extra["cve_ids"] = entry.cve_ids
    if entry.affected_products:
        extra["affected_products"] = entry.affected_products
    if entry.solution:
        extra["solution"] = entry.solution
    if entry.raw_pub_date:
        extra["raw_pub_date"] = entry.raw_pub_date

    # Add severity label if available
    if entry.severity:
        labels.append(f"severity:{entry.severity.lower()}")

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": entry.advisory_id,
            "origin_url": entry.link,
            "manifest": MANIFEST,
            "manifest_hash": MANIFEST_HASH,
            "manifest_version": MANIFEST_VERSION,
        },
        "content": {
            "title": entry.title,
            "summary": summary,
            "body_text": body_text,
            "published_at": entry.published_at,
            "language": "en",
        },
        "severity": entry.severity,
        "fetched_at": entry.fetched_at,
        "labels": labels,
        "topics": topics,
        "extra": extra,
        "raw": {
            "feed_entry": {
                "advisory_id": entry.advisory_id,
                "title": entry.title,
                "link": entry.link,
                "description": entry.description,
                "cve_ids": entry.cve_ids,
                "published_at": entry.published_at,
                "affected_products": entry.affected_products,
                "solution": entry.solution,
                "severity": entry.severity,
            }
        },
    }


# ---------------------------------------------------------------------------
# Collect
# ---------------------------------------------------------------------------

def collect(
    *,
    limit: int | None = None,
    force: bool = False,
) -> tuple[list[dict], dict]:
    """Collect Advisory bulletins from ALAS RSS feed."""
    limit = limit or DEFAULT_LIMIT
    cached_ids = set() if force else load_cache()
    logger.info("Cache loaded: %d Advisory IDs", len(cached_ids))

    entries = list(fetch_feed())
    entries.sort(
        key=lambda e: e.published_at or "",
        reverse=True,
    )

    # Filter out cached items
    new_entries: list[FeedEntry] = []
    skipped_count = 0
    for entry in entries:
        if entry.advisory_id in cached_ids:
            skipped_count += 1
            continue
        new_entries.append(entry)

    logger.info("New entries: %d, Skipped (cached): %d", len(new_entries), skipped_count)

    # Apply limit
    if limit and len(new_entries) > limit:
        new_entries = new_entries[:limit]

    # Enrich entries with detail API and normalize to bulletins
    bulletins: list[dict] = []
    for entry in new_entries:
        try:
            enriched_entry = enrich_entry(entry)
            bulletin = normalize(enriched_entry)
            bulletins.append(bulletin)
        except Exception as e:
            logger.error("Failed to process entry %s: %s", entry.advisory_id, e)

    # Update cache
    if bulletins and not force:
        new_ids = {entry.advisory_id for entry in new_entries}
        updated_cache = cached_ids | new_ids
        save_cache(updated_cache)
        logger.info("Cache updated: %d Advisory IDs", len(updated_cache))

    stats = {
        "items_processed": len(entries),
        "items_created": len(bulletins),
        "items_skipped_cache": skipped_count,
    }

    return bulletins, stats


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
    logger.info(
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
        logger.error("SECLENS_URL environment variable is required")
        sys.exit(1)
    if not SECLENS_TOKEN:
        logger.error("SECLENS_TOKEN environment variable is required")
        sys.exit(1)

    bulletins, stats = collect()

    if not bulletins:
        logger.info("No items to push")
        logger.info("Done: processed=%d new=0", stats["items_processed"])
        return

    result = push_to_seclens(bulletins)
    logger.info(
        "Done: processed=%d fetched=%d accepted=%s duplicates=%s",
        stats["items_processed"],
        len(bulletins),
        result.get("accepted", 0),
        result.get("duplicates", 0),
    )


if __name__ == "__main__":
    main()
