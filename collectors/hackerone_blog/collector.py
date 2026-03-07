"""HackerOne Blog collector.

Fetches security blog posts from the HackerOne official blog and pushes
them to a SecLens server. Fully standalone - no SecLens app dependencies.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 6 hours (21600s)
"""
from __future__ import annotations

import json
import logging
import os
import sys
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    from shared.manifest import load_manifest_for_slug
    from shared.time_helpers import now_utc_iso, parse_first
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from shared.manifest import load_manifest_for_slug
    from shared.time_helpers import now_utc_iso, parse_first

import requests
from bs4 import BeautifulSoup, Tag

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")

SLUG = "hackerone_blog"
BASE_URL = "https://www.hackerone.com"
LIST_URL = os.environ.get("HACKERONE_LIST_URL", f"{BASE_URL}/blog")
USER_AGENT = "SeclensCollector/2.0 (hackerone_blog)"
REQUEST_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "User-Agent": USER_AGENT,
}
REQUEST_TIMEOUT = 30
STATE_FILE_NAME = ".cursor"
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SLUG)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SLUG)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clean_text(value: str | None) -> str | None:
    if not value:
        return None
    normalised = unicodedata.normalize("NFKC", value)
    collapsed = " ".join(normalised.replace("\xa0", " ").replace("\u202f", " ").split())
    return collapsed or None


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _slugify(value: str | None) -> str | None:
    if not value:
        return None
    normalized = unicodedata.normalize("NFKD", value).lower()
    parts: list[str] = []
    for char in normalized:
        if char.isalnum():
            parts.append(char)
        elif char in {" ", "-", "_", "/", "."}:
            parts.append("-")
    slug = "".join(parts).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or None


def _slug_from_url(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    if not path:
        return None
    slug = path.rsplit("/", 1)[-1]
    return slug or None


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
# Fetch
# ---------------------------------------------------------------------------


@dataclass
class FetchParams:
    """Parameters controlling HackerOne blog fetching."""
    list_url: str = LIST_URL
    limit: int | None = 10


class HackerOneBlogCollector:
    """Fetch and normalise HackerOne blog entries."""

    def __init__(self, session: requests.Session | None = None) -> None:
        self.session = session or requests.Session()
        self.session.headers.update(REQUEST_HEADERS)

    # ---- Fetch ---------------------------------------------------------
    def fetch(self, params: FetchParams) -> Sequence[dict[str, Any]]:
        listing = self._fetch_listing(params.list_url, params.limit)
        entries: list[dict[str, Any]] = []
        for item in listing:
            detail: dict[str, Any] | None = None
            detail_url = item.get("url")
            if detail_url:
                try:
                    detail = self._fetch_detail(detail_url)
                except Exception as exc:
                    logger.exception("Failed to fetch HackerOne detail %s", detail_url, exc_info=exc)
            entries.append({"listing": item, "detail": detail})
        return entries

    def _fetch_listing(self, list_url: str, limit: int | None) -> list[dict[str, Any]]:
        response = self.session.get(list_url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        rows = soup.select("div.views-row article.node--type-blog")

        results: list[dict[str, Any]] = []
        for row in rows:
            parsed = self._parse_listing_article(row, base_url=list_url)
            if not parsed:
                continue
            results.append(parsed)
            if limit is not None and len(results) >= limit:
                break
        return results

    def _parse_listing_article(self, article: Tag, base_url: str) -> dict[str, Any] | None:
        anchor = article.find("a", href=True, rel=lambda value: value and "bookmark" in value)
        if not anchor:
            anchor = article.find("a", href=True)
        if not anchor:
            return None
        href = anchor.get("href")
        if not href:
            return None
        url = urljoin(base_url, href)

        title = None
        title_span = article.select_one(".field--name-title")
        if title_span:
            title = _clean_text(title_span.get_text(" ", strip=True))
        if not title:
            title = _clean_text(anchor.get_text(" ", strip=True))
        if not title:
            return None

        summary = None
        summary_field = article.select_one(".field--name-body")
        if summary_field:
            summary = _clean_text(summary_field.get_text(" ", strip=True))

        time_node = article.find("time")
        published_hint = None
        if time_node:
            published_hint = _clean_text(time_node.get("datetime") or time_node.get_text(" ", strip=True))

        topics: list[str] = []
        for topic_anchor in article.select(".field--name-field-blog-topic a"):
            topic = _clean_text(topic_anchor.get_text(" ", strip=True))
            if topic:
                topics.append(topic)

        solutions: list[str] = []
        for solution_anchor in article.select(".field--name-field-solutions a"):
            solution = _clean_text(solution_anchor.get_text(" ", strip=True))
            if solution:
                solutions.append(solution)

        image_url = None
        image = article.find("img")
        if image and image.get("src"):
            image_url = urljoin(base_url, image["src"])

        return {
            "title": title,
            "url": url,
            "summary": summary,
            "published_hint": published_hint,
            "topics": _dedupe(topics),
            "solutions": _dedupe(solutions),
            "image": image_url,
        }

    def _fetch_detail(self, detail_url: str) -> dict[str, Any]:
        response = self.session.get(detail_url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        article = soup.select_one("article.node--type-blog")

        title = None
        if article:
            title_field = article.select_one(".field--name-title")
            if title_field:
                title = _clean_text(title_field.get_text(" ", strip=True))
        if not title:
            og_title = soup.find("meta", attrs={"property": "og:title"})
            if og_title and og_title.get("content"):
                title = _clean_text(og_title["content"])

        summary = None
        description_meta = soup.find("meta", attrs={"property": "og:description"})
        if description_meta and description_meta.get("content"):
            summary = _clean_text(description_meta["content"])
        if not summary and article:
            summary_field = article.select_one(".field--name-body p")
            if summary_field:
                summary = _clean_text(summary_field.get_text(" ", strip=True))

        canonical_url = None
        canonical_link = soup.find("link", attrs={"rel": "canonical"})
        if canonical_link and canonical_link.get("href"):
            canonical_url = canonical_link["href"]

        body_text = None
        body_html = None
        if article:
            body_field = article.select_one(".field--name-body")
            if body_field:
                paragraphs: list[str] = []
                for element in body_field.find_all(["p", "li"]):
                    text = _clean_text(element.get_text(" ", strip=True))
                    if text:
                        paragraphs.append(text)
                if paragraphs:
                    body_text = "\n\n".join(paragraphs)
                body_html = body_field.decode_contents()

        published_time = None
        authors: list[str] = []
        taxonomy: dict[str, list[str]] = {}
        page_data = self._extract_page_data(soup)
        if page_data:
            published_time = page_data.get("publishedDate") or published_time
            for author in page_data.get("author") or []:
                fullname = author.get("fullName") or " ".join(
                    part for part in [author.get("firstName"), author.get("lastName")] if part
                )
                name = _clean_text(fullname)
                if name:
                    authors.append(name)
            taxonomy_terms = page_data.get("taxonomyTerms") or []
            for term in taxonomy_terms:
                vocabulary = term.get("vocabulary")
                name = _clean_text(term.get("name"))
                if not vocabulary or not name:
                    continue
                taxonomy.setdefault(vocabulary, [])
                taxonomy[vocabulary].append(name)

        modified_time = None
        modified_meta = soup.find("meta", attrs={"property": "article:modified_time"})
        if modified_meta and modified_meta.get("content"):
            modified_time = _clean_text(modified_meta["content"])

        hero_image = None
        og_image = soup.find("meta", attrs={"property": "og:image"})
        if og_image and og_image.get("content"):
            hero_image = og_image["content"]

        authors = _dedupe(authors)
        taxonomy = {key: _dedupe(values) for key, values in taxonomy.items()}

        return {
            "title": title,
            "summary": summary,
            "canonical_url": canonical_url,
            "published_time": published_time,
            "modified_time": modified_time,
            "authors": authors,
            "taxonomy": taxonomy,
            "body_text": body_text,
            "body_html": body_html,
            "hero_image": hero_image,
        }

    @staticmethod
    def _extract_page_data(soup: BeautifulSoup) -> dict[str, Any] | None:
        script = soup.find("script", attrs={"type": "application/json", "data-drupal-selector": "drupal-settings-json"})
        if not script or not script.string:
            return None
        try:
            settings = json.loads(script.string)
        except json.JSONDecodeError:
            logger.warning("Failed to decode drupal settings JSON")
            return None
        page_data = settings.get("hackeronePageData")
        if isinstance(page_data, dict):
            return page_data
        return None


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(entry: dict[str, Any]) -> dict:
    """Convert a fetched entry to a SecLens bulletin dict."""
    listing = entry.get("listing") or {}
    detail = entry.get("detail") or {}

    origin_url = detail.get("canonical_url") or listing.get("url")
    title = detail.get("title") or listing.get("title") or origin_url or ""
    summary = detail.get("summary") or listing.get("summary")
    body_text = detail.get("body_text")

    fetched_at = now_utc_iso()
    published_at = parse_first(
        [
            (detail.get("published_time"), "detail.page_data.publishedDate"),
            (listing.get("published_hint"), "listing.time.datetime"),
        ],
        default_tz="UTC",
    )

    external_id = _slug_from_url(origin_url) or origin_url

    taxonomy = detail.get("taxonomy") or {}
    authors = detail.get("authors") or []

    def _label(prefix: str, values: Iterable[str]) -> list[str]:
        labels: list[str] = []
        for value in values:
            name = _clean_text(value)
            slug = _slugify(name)
            if name and slug:
                labels.append(f"{prefix}:{slug}")
        return labels

    labels: list[str] = ["vendor:hackerone"]
    labels.extend(_label("author", authors))
    for vocabulary, values in taxonomy.items():
        vocab_slug = _slugify(vocabulary) or vocabulary.lower()
        for value in values:
            term_slug = _slugify(value)
            if term_slug:
                labels.append(f"{vocab_slug}:{term_slug}")

    listing_topics = listing.get("topics") or []
    listing_solutions = listing.get("solutions") or []
    if listing_topics:
        labels.extend(_label("blog_topic", listing_topics))
    if listing_solutions:
        labels.extend(_label("h1_solution", listing_solutions))

    labels = _dedupe(labels)

    topics = ["security-blog", "hacker-community"]

    extra: dict[str, Any] = {
        "authors": authors,
        "taxonomy": taxonomy,
        "listing_topics": listing_topics,
        "listing_solutions": listing_solutions,
        "listing_image": listing.get("image"),
        "hero_image": detail.get("hero_image"),
        "modified_time": detail.get("modified_time"),
    }
    if summary and summary != listing.get("summary"):
        extra["detail_summary"] = summary
    if detail.get("body_html"):
        extra["body_html"] = detail["body_html"]

    return {
        "source": {
            "source_slug": SLUG,
            "external_id": external_id,
            "origin_url": origin_url,
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
        "fetched_at": fetched_at,
        "labels": labels,
        "topics": topics,
        "extra": extra,
        "raw": {"listing": listing, "detail": detail},
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
    logger.info("Server response: accepted=%s, duplicates=%s", result.get("accepted"), result.get("duplicates"))
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

    collector = HackerOneBlogCollector()
    entries = collector.fetch(FetchParams())
    latest_cursor = None
    if entries:
        listing = entries[0].get("listing") or {}
        latest_cursor = _slug_from_url(listing.get("url")) or listing.get("url")
    previous_cursor = load_cursor()
    if previous_cursor:
        filtered: list[dict[str, Any]] = []
        for entry in entries:
            listing = entry.get("listing") or {}
            cursor_value = _slug_from_url(listing.get("url")) or listing.get("url") or ""
            if cursor_value == previous_cursor:
                break
            filtered.append(entry)
        entries = filtered
        logger.info(
            "Cursor check: previous=%s, pending=%d",
            previous_cursor,
            len(entries),
        )

    bulletins = []
    for entry in entries:
        try:
            bulletins.append(normalize(entry))
        except Exception as exc:
            logger.exception("Failed to normalise HackerOne blog entry: %s", entry, exc_info=exc)

    if not bulletins:
        logger.info("No items to push")
        return

    result = push_to_seclens(bulletins)
    if latest_cursor:
        save_cursor(latest_cursor)
    logger.info(
        "Done: fetched=%d accepted=%s duplicates=%s",
        len(bulletins),
        result.get("accepted", 0),
        result.get("duplicates", 0),
    )


if __name__ == "__main__":
    main()
