"""Doonsec WeChat RSS collector - standalone version.

Fetches security articles from the Doonsec WeChat RSS aggregator and pushes
them to a SecLens server. Supports cache-based deduplication and optional
whitelist filtering.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 30 minutes (1800s)
"""
from __future__ import annotations

import html
import json
import logging
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

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
FEED_URL = os.environ.get("DOONSEC_FEED_URL", "https://wechat.doonsec.com/rss.xml")

SOURCE_SLUG = "doonsec_wechat"
USER_AGENT = "SeclensCollector/2.0 (doonsec_wechat)"
REQUEST_TIMEOUT = 30
REQUEST_HEADERS = {
    "Accept": "application/rss+xml, application/xml;q=0.9, */*;q=0.8",
    "User-Agent": USER_AGENT,
}
MAX_CACHE_SIZE = 2000
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)

_HEX_ESCAPE_RE = re.compile(r"\\x([0-9A-Fa-f]{2})")
_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9A-Fa-f]{4})")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

CACHE_FILE = Path(__file__).parent / ".cursor"


def _load_cache() -> set[str]:
    """Load cached article URLs from JSON file."""
    try:
        with CACHE_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                items = data.get("article_urls", [])
                if isinstance(items, list):
                    return set(items)
        return set()
    except (FileNotFoundError, json.JSONDecodeError):
        return set()


def _save_cache(article_urls: set[str]) -> None:
    """Save article URLs to cache, keeping only the latest MAX_CACHE_SIZE items."""
    urls_list = list(article_urls)[-MAX_CACHE_SIZE:]
    with CACHE_FILE.open("w", encoding="utf-8") as f:
        json.dump(
            {
                "article_urls": urls_list,
                "updated_at": now_utc_iso(),
                "count": len(urls_list),
            },
            f,
            indent=2,
            ensure_ascii=False,
        )


# ---------------------------------------------------------------------------
# Text cleaning helpers
# ---------------------------------------------------------------------------


def _trim(text: str | None) -> str | None:
    if not text:
        return None
    cleaned = text.strip()
    return cleaned or None


def _clean_text(value: str | None) -> str | None:
    """Normalize backslash-escaped characters and HTML entities."""
    if value is None:
        return None

    cleaned = value
    if "\\" in cleaned:
        cleaned = cleaned.replace('\\"', '"').replace("\\'", "'")

        def _hex_repl(match: re.Match[str]) -> str:
            try:
                return chr(int(match.group(1), 16))
            except ValueError:
                return match.group(0)

        def _unicode_repl(match: re.Match[str]) -> str:
            try:
                return chr(int(match.group(1), 16))
            except ValueError:
                return match.group(0)

        cleaned = _HEX_ESCAPE_RE.sub(_hex_repl, cleaned)
        cleaned = _UNICODE_ESCAPE_RE.sub(_unicode_repl, cleaned)
        cleaned = cleaned.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r")
        cleaned = cleaned.replace("\\\\", "\\")

    return html.unescape(cleaned)


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


def fetch_feed(feed_url: str = FEED_URL, limit: int | None = None) -> list[dict]:
    """Fetch and parse the Doonsec WeChat RSS feed."""
    logger.info("Fetching feed: %s", feed_url)
    session = requests.Session()
    session.headers.update(REQUEST_HEADERS)
    try:
        response = session.get(feed_url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except requests.RequestException as exc:
        logger.warning("Failed to fetch Doonsec feed: %s", exc)
        return []

    try:
        root = ET.fromstring(response.content)
    except ET.ParseError as exc:
        logger.warning("Failed to parse Doonsec feed XML: %s", exc)
        return []
    channel = root.find("channel")
    items = channel.findall("item") if channel is not None else root.findall(".//item")

    serialized: list[dict] = []
    for item in items:
        serialized.append(
            {
                "title": _trim(item.findtext("title")) or "",
                "link": _trim(item.findtext("link")),
                "description": _trim(item.findtext("description")),
                "author": _trim(item.findtext("author")),
                "category": _trim(item.findtext("category")),
                "pub_date": _trim(item.findtext("pubDate")),
                "raw_xml": ET.tostring(item, encoding="unicode"),
            }
        )
        if limit and len(serialized) >= limit:
            break

    logger.info("Fetched %d items from feed", len(serialized))
    return serialized


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(item: dict) -> dict:
    """Convert a feed entry dict to a SecLens bulletin dict."""
    return _normalize_with_content(item)


def _normalize_with_content(
    item: dict,
    *,
    fetched_body: str | None = None,
    fetched_title: str | None = None,
    fetched_meta: dict | None = None,
) -> dict:
    """Convert a feed entry dict to a SecLens bulletin dict, optionally with fetched article body."""
    published_at = parse_first(
        [(item.get("pub_date"), "item.pubDate")],
        default_tz="Asia/Shanghai",
    )

    origin_url = _clean_text(item.get("link"))
    title = fetched_title or _clean_text(item.get("title")) or (origin_url or "")
    description = _clean_text(item.get("description"))
    author = _clean_text(item.get("author"))
    category = _clean_text(item.get("category"))

    external_id = origin_url or item.get("link")

    labels: list[str] = []
    if category:
        labels.append(f"category:{category.lower()}")
    if author:
        labels.append(f"author:{author.lower()}")

    extra: dict = {
        "author": author,
        "category": category,
        "content_fetched": fetched_body is not None,
    }
    if fetched_meta:
        extra["fetched_meta"] = fetched_meta

    raw_payload = {k: v for k, v in item.items() if k != "raw_xml"}
    if item.get("raw_xml"):
        raw_payload["raw_xml"] = item["raw_xml"]

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
            "summary": description,
            "body_text": fetched_body or description,
            "published_at": published_at,
            "language": "zh",
        },
        "severity": None,
        "fetched_at": now_utc_iso(),
        "labels": labels,
        "topics": ["security-news"],
        "extra": extra,
        "raw": raw_payload,
    }


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
        result.get("accepted"), result.get("duplicates"),
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

    # Load whitelist config from environment
    whitelist_enabled = os.environ.get("DOONSEC_WHITELIST_ENABLED", "").lower() in ("1", "true", "yes")
    whitelist_raw = os.environ.get("DOONSEC_WHITELIST_AUTHORS", "")
    whitelist_authors = [a.strip() for a in whitelist_raw.split(",") if a.strip()] if whitelist_raw else []
    fetch_content_enabled = os.environ.get("DOONSEC_FETCH_CONTENT_ENABLED", "").lower() in ("1", "true", "yes")
    fetch_timeout = int(os.environ.get("DOONSEC_FETCH_CONTENT_TIMEOUT", "30") or "30")
    fetch_limit = int(os.environ.get("DOONSEC_FETCH_CONTENT_LIMIT", "10") or "10")
    browser_proxy = (os.environ.get("DOONSEC_BROWSER_PROXY") or "").strip() or None

    cached_urls = _load_cache()
    logger.info("Loaded cache: %d article URLs already seen", len(cached_urls))

    entries = fetch_feed()

    # Filter out cached entries
    skipped_cache = 0
    new_entries = []
    for entry in entries:
        url = entry.get("link")
        if url and url in cached_urls:
            skipped_cache += 1
        else:
            new_entries.append(entry)

    logger.info("After cache filtering: %d new entries, %d cached", len(new_entries), skipped_cache)

    # Apply whitelist filtering if enabled
    skipped_whitelist = 0
    if whitelist_enabled and whitelist_authors:
        whitelist_set = set(whitelist_authors)
        filtered = []
        for entry in new_entries:
            category = entry.get("category") or entry.get("author")
            if category and category in whitelist_set:
                filtered.append(entry)
            else:
                skipped_whitelist += 1
        logger.info("After whitelist filtering: %d entries, %d skipped", len(filtered), skipped_whitelist)
        new_entries = filtered

    fetched_contents: dict[str, tuple[str | None, str | None, dict | None]] = {}
    content_fetch_failures = 0
    if fetch_content_enabled and new_entries:
        logger.info("Content fetch enabled; target entries=%d", min(len(new_entries), fetch_limit))
        try:
            try:
                from .wechat_fetcher import WeChatFetcher
            except ImportError:
                from wechat_fetcher import WeChatFetcher

            with WeChatFetcher(proxy_url=browser_proxy) as fetcher:
                for entry in new_entries[:fetch_limit]:
                    url = entry.get("link")
                    if not url:
                        continue
                    title, body, meta = fetcher.fetch(url, timeout=fetch_timeout)
                    fetched_contents[url] = (title, body, meta)
                    if body:
                        logger.info("Fetched full content for %s", url)
                    else:
                        content_fetch_failures += 1
                        logger.warning("Failed to fetch full content for %s: %s", url, (meta or {}).get("error"))
        except ImportError as exc:
            logger.warning("WeChat fetch dependencies unavailable: %s", exc)
        except Exception as exc:
            logger.warning("WeChat content fetch aborted: %s", exc)

    # Normalize entries
    bulletins = []
    new_urls = set()
    for entry in new_entries:
        url = entry.get("link")
        fetched_title = None
        fetched_body = None
        fetched_meta = None
        if url and url in fetched_contents:
            fetched_title, fetched_body, fetched_meta = fetched_contents[url]
        bulletin = _normalize_with_content(
            entry,
            fetched_body=fetched_body,
            fetched_title=fetched_title,
            fetched_meta=fetched_meta,
        )
        bulletins.append(bulletin)
        if url:
            new_urls.add(url)

    # Update cache
    if new_urls:
        updated_cache = cached_urls | new_urls
        _save_cache(updated_cache)
        logger.info("Updated cache: added %d new URLs, total %d", len(new_urls), len(updated_cache))

    if not bulletins:
        logger.info("No new items to push")
        return

    result = push_to_seclens(bulletins)
    logger.info(
        "Done: fetched=%d, accepted=%s, duplicates=%s, cached=%d, whitelist_filtered=%d, content_fetch_failures=%d",
        len(bulletins),
        result.get("accepted", 0),
        result.get("duplicates", 0),
        skipped_cache,
        skipped_whitelist,
        content_fetch_failures,
    )


if __name__ == "__main__":
    main()
