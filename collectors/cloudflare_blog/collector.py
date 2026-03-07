"""Cloudflare Blog collector.

Fetches technical blog posts from the Cloudflare Blog homepage and pushes
them to a SecLens server. Fully standalone - no SecLens app dependencies.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 90 minutes (5400s)
"""
from __future__ import annotations

import logging
import os
import sys
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup, Tag

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
SOURCE_SLUG = "cloudflare_blog"
DEFAULT_LIST_URL = "https://blog.cloudflare.com/"
USER_AGENT = "SeclensCollector/2.0 (cloudflare_blog)"
REQUEST_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "User-Agent": USER_AGENT,
}
REQUEST_TIMEOUT = 30
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass
class FetchParams:
    list_url: str = DEFAULT_LIST_URL
    limit: int | None = 10


def _clean_text(value: str | None) -> str | None:
    if not value:
        return None
    normalised = unicodedata.normalize("NFKC", value)
    collapsed = " ".join(normalised.split())
    return collapsed or None


def _unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _looks_like_date(text: str | None) -> bool:
    if not text:
        return False
    if len(text) != 10:
        return False
    if text[4] != "-" or text[7] != "-":
        return False
    year, month, day = text[:4], text[5:7], text[8:]
    return year.isdigit() and month.isdigit() and day.isdigit()


def _slug_from_url(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    if not path:
        return None
    slug = path.rsplit("/", 1)[-1]
    return slug or None


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


class CloudflareBlogCollector:
    """Fetch and normalise Cloudflare blog entries."""

    def __init__(self, session: requests.Session | None = None) -> None:
        self.session = session or requests.Session()
        self.session.headers.update(REQUEST_HEADERS)

    def fetch(self, params: FetchParams) -> Sequence[dict]:
        listing = self._fetch_listing(params.list_url, params.limit)
        entries: list[dict] = []
        for item in listing:
            detail = self._fetch_detail(item["url"])
            merged = {
                "listing": item,
                "detail": detail,
            }
            entries.append(merged)
        return entries

    def _fetch_listing(self, list_url: str, limit: int | None) -> list[dict]:
        logger.info("Fetching listing: %s", list_url)
        response = self.session.get(list_url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        articles = soup.find_all("article")
        items: list[dict] = []
        for article in articles:
            parsed = self._parse_listing_article(article, base_url=list_url)
            if not parsed:
                continue
            items.append(parsed)
            if limit and len(items) >= limit:
                break
        logger.info("Found %d listing items", len(items))
        return items

    def _parse_listing_article(self, article: Tag, base_url: str) -> dict | None:
        title_anchor = article.find("a", attrs={"data-testid": "post-title"})
        if not title_anchor:
            title_anchor = article.find("a", href=True)
        if not title_anchor:
            return None
        href = title_anchor.get("href")
        if not href:
            return None
        origin_url = urljoin(base_url, href)
        heading = title_anchor.find(["h1", "h2", "h3"])
        title = _clean_text(heading.get_text()) if heading else _clean_text(title_anchor.get_text())
        if not title:
            return None

        date_node = article.find(attrs={"data-testid": "post-date"})
        published_hint = None
        if date_node:
            published_hint = _clean_text(date_node.get("datetime") or date_node.get_text())
        if not published_hint:
            time_node = article.find("time")
            if time_node:
                published_hint = _clean_text(time_node.get("datetime") or time_node.get_text())

        summary_node = article.find(attrs={"data-testid": "post-content"})
        summary = _clean_text(summary_node.get_text()) if summary_node else None
        if not summary:
            for paragraph in article.find_all("p"):
                candidate = _clean_text(paragraph.get_text())
                if not candidate or _looks_like_date(candidate):
                    continue
                summary = candidate
                break

        authors: list[str] = []
        for anchor in article.select("ul.author-lists a"):
            name = _clean_text(anchor.get_text())
            if not name:
                continue
            authors.append(name)

        image = None
        img = article.find("img")
        if img and img.get("src"):
            image = urljoin(base_url, img["src"])

        return {
            "title": title,
            "url": origin_url,
            "summary": summary,
            "published_hint": published_hint,
            "authors": _unique(authors),
            "image": image,
        }

    def _fetch_detail(self, url: str) -> dict:
        logger.info("Fetching detail: %s", url)
        response = self.session.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        article = soup.find("article", class_=lambda value: value and "post-full" in value.split())
        if not article:
            article = soup.find("article")

        title = None
        title_meta = soup.find("meta", attrs={"property": "og:title"})
        if title_meta and title_meta.get("content"):
            title = _clean_text(title_meta["content"])
        if not title and article:
            heading = article.find(["h1", "h2"])
            if heading:
                title = _clean_text(heading.get_text())

        summary = None
        summary_meta = soup.find("meta", attrs={"property": "og:description"})
        if summary_meta and summary_meta.get("content"):
            summary = _clean_text(summary_meta["content"])
        if not summary:
            description_meta = soup.find("meta", attrs={"name": "description"})
            if description_meta and description_meta.get("content"):
                summary = _clean_text(description_meta["content"])

        canonical = None
        canonical_link = soup.find("link", attrs={"rel": "canonical"})
        if canonical_link and canonical_link.get("href"):
            canonical = canonical_link["href"]

        published_time = None
        published_meta = soup.find("meta", attrs={"property": "article:published_time"})
        if published_meta and published_meta.get("content"):
            published_time = _clean_text(published_meta["content"])

        modified_time = None
        modified_meta = soup.find("meta", attrs={"property": "article:modified_time"})
        if modified_meta and modified_meta.get("content"):
            modified_time = _clean_text(modified_meta["content"])

        tags: list[str] = []
        for tag_meta in soup.find_all("meta", attrs={"property": "article:tag"}):
            content = _clean_text(tag_meta.get("content"))
            if content:
                tags.append(content)

        authors = []
        if article:
            for anchor in article.select("ul.author-lists a"):
                name = _clean_text(anchor.get_text())
                if name:
                    authors.append(name)
        if not authors:
            author_meta = soup.find("meta", attrs={"name": "twitter:data1"})
            if author_meta and author_meta.get("content"):
                for part in author_meta["content"].split(","):
                    name = _clean_text(part)
                    if name:
                        authors.append(name)

        authors = _unique(authors)
        tags = _unique(tags)

        body_text = None
        body_html = None
        if article:
            paragraphs: list[str] = []
            for paragraph in article.find_all("p"):
                text = _clean_text(paragraph.get_text())
                if not text or _looks_like_date(text):
                    continue
                paragraphs.append(text)
            if paragraphs:
                body_text = "\n\n".join(paragraphs)
            body_html = article.decode_contents()

        hero_image = None
        og_image = soup.find("meta", attrs={"property": "og:image"})
        if og_image and og_image.get("content"):
            hero_image = og_image["content"]

        return {
            "title": title,
            "summary": summary,
            "canonical_url": canonical,
            "published_time": published_time,
            "modified_time": modified_time,
            "tags": tags,
            "authors": authors,
            "body_text": body_text,
            "body_html": body_html,
            "hero_image": hero_image,
        }


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(entry: dict) -> dict:
    """Convert a fetched entry to a SecLens bulletin dict."""
    listing = entry.get("listing") or {}
    detail = entry.get("detail") or {}
    origin_url: str | None = listing.get("url") or detail.get("canonical_url")

    title = detail.get("title") or listing.get("title") or origin_url or ""
    summary = detail.get("summary") or listing.get("summary")
    body_text = detail.get("body_text")

    published_at = parse_first(
        [
            (detail.get("published_time"), "detail.article:published_time"),
            (listing.get("published_hint"), "listing.post_date"),
        ],
        default_tz="UTC",
    )

    canonical_url = detail.get("canonical_url") or origin_url
    external_id = _slug_from_url(canonical_url or origin_url) or canonical_url or origin_url

    tags = detail.get("tags") or []
    authors = detail.get("authors") or listing.get("authors") or []

    def _label(prefix: str, values: Iterable[str]) -> list[str]:
        result: list[str] = []
        for value in values:
            cleaned = _clean_text(value)
            if not cleaned:
                continue
            lowered = " ".join(cleaned.lower().split())
            result.append(f"{prefix}:{lowered}")
        return result

    labels = _label("tag", tags) + _label("author", authors)
    topics = ["tech-blog"]

    extra: dict = {
        "tags": tags,
        "authors": authors,
        "listing_image": listing.get("image"),
        "hero_image": detail.get("hero_image"),
        "modified_time": detail.get("modified_time"),
    }

    raw = {
        "listing": listing,
        "detail": detail,
    }

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": external_id,
            "origin_url": canonical_url,
            "manifest": MANIFEST,
            "manifest_hash": MANIFEST_HASH,
            "manifest_version": MANIFEST_VERSION,
        },
        "content": {
            "title": title,
            "summary": summary,
            "body_text": body_text,
            "published_at": published_at,
            "language": "en",
        },
        "severity": None,
        "fetched_at": now_utc_iso(),
        "labels": labels,
        "topics": topics,
        "extra": extra,
        "raw": raw,
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

    collector = CloudflareBlogCollector()
    entries = collector.fetch(FetchParams())
    logger.info("Fetched %d entries", len(entries))

    bulletins = [normalize(entry) for entry in entries]

    if not bulletins:
        logger.info("No items to push")
        return

    result = push_to_seclens(bulletins)
    logger.info(
        "Done: %d fetched, %d accepted, %d duplicates",
        len(bulletins),
        result.get("accepted", 0),
        result.get("duplicates", 0),
    )


if __name__ == "__main__":
    main()
