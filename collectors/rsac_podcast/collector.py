"""RSA Conference podcast collector from SoundCloud.

Fetches podcast episodes from RSA Conference on SoundCloud and pushes
them to a SecLens server. Fully standalone - no SecLens app dependencies.

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
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

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
DEFAULT_LIST_URL = os.environ.get(
    "RSAC_LIST_URL",
    "https://soundcloud.com/rsa-conference/tracks",
)
OEMBED_API_URL = "https://soundcloud.com/oembed"
SOURCE_SLUG = "rsac_podcast"
USER_AGENT = "SeclensCollector/2.0 (rsac_podcast)"
REQUEST_TIMEOUT = 30
REQUEST_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "User-Agent": USER_AGENT,
}
CACHE_FILE = Path(__file__).parent / ".cursor"
CACHE_SIZE_LIMIT = 100
DEFAULT_LIMIT = 20
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clean_text(value: str | None) -> str | None:
    """Clean and normalize text."""
    if not value:
        return None
    normalized = unicodedata.normalize("NFKC", value)
    collapsed = " ".join(normalized.split())
    return collapsed or None


def _slug_from_url(url: str | None) -> str | None:
    """Extract slug from URL."""
    if not url:
        return None
    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    if not path:
        return None
    slug = path.rsplit("/", 1)[-1]
    return slug or None


def _extract_track_id_from_iframe(iframe_url: str | None) -> str | None:
    """Extract track ID from SoundCloud iframe URL."""
    if not iframe_url:
        return None
    match = re.search(r"tracks%2F(\d+)", iframe_url)
    if match:
        return match.group(1)
    match = re.search(r"tracks/(\d+)", iframe_url)
    if match:
        return match.group(1)
    return None


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


class CacheManager:
    """Manage local cache to avoid re-fetching seen items."""

    def __init__(self, cache_file: Path, size_limit: int = CACHE_SIZE_LIMIT):
        self.cache_file = cache_file
        self.size_limit = size_limit
        self.cache: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if self.cache_file.exists():
            try:
                with open(self.cache_file, encoding="utf-8") as f:
                    self.cache = json.load(f)
                logger.info("Loaded %d items from cache", len(self.cache))
            except Exception as e:
                logger.warning("Failed to load cache: %s", e)
                self.cache = {}

    def save(self) -> None:
        try:
            if len(self.cache) > self.size_limit:
                items = sorted(self.cache.items(), key=lambda x: x[1], reverse=True)
                self.cache = dict(items[: self.size_limit])
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, indent=2)
            logger.info("Saved %d items to cache", len(self.cache))
        except Exception as e:
            logger.warning("Failed to save cache: %s", e)

    def is_cached(self, external_id: str) -> bool:
        return external_id in self.cache

    def add(self, external_id: str) -> None:
        self.cache[external_id] = datetime.now(timezone.utc).isoformat()  # noqa: UP017


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class RSACPodcastCollector:
    """Fetch and normalize RSA Conference podcast episodes from SoundCloud."""

    def __init__(self, session: requests.Session | None = None) -> None:
        self.session = session or requests.Session()
        self.session.headers.update(REQUEST_HEADERS)
        self.cache = CacheManager(CACHE_FILE)
        self.items_skipped_cache = 0

    def fetch_track_links(self, list_url: str = DEFAULT_LIST_URL) -> list[str]:
        """Fetch track links from the list page."""
        logger.info("Fetching track links from %s", list_url)
        response = self.session.get(list_url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        links = soup.find_all("a", href=True)

        track_links: list[str] = []
        for link in links:
            href = link["href"]
            if "/rsa-conference/" in href and href not in [
                "/rsa-conference",
                "/rsa-conference/tracks",
            ]:
                full_url = urljoin(list_url, href)
                if full_url not in track_links:
                    track_links.append(full_url)

        logger.info("Found %d track links", len(track_links))
        return track_links

    def fetch_oembed_data(self, track_url: str) -> dict | None:
        """Fetch track data using oEmbed API."""
        try:
            params = {"url": track_url, "format": "json"}
            response = self.session.get(OEMBED_API_URL, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            logger.debug("Fetched oEmbed data for %s", track_url)
            return data
        except Exception as e:
            logger.warning("Failed to fetch oEmbed for %s: %s", track_url, e)
            return None

    def fetch_track_metadata(self, track_url: str) -> dict | None:
        """Fetch additional metadata from track page."""
        try:
            response = self.session.get(track_url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")

            meta_data = {}
            for meta in soup.find_all("meta"):
                if meta.get("property"):
                    meta_data[meta["property"]] = meta.get("content")
                elif meta.get("name"):
                    meta_data[meta["name"]] = meta.get("content")

            created_at = None
            time_elem = soup.find("time")
            if time_elem:
                created_at = time_elem.get("datetime") or time_elem.get_text()

            return {
                "url": track_url,
                "meta": meta_data,
                "created_at": created_at,
            }
        except Exception as e:
            logger.warning("Failed to fetch metadata for %s: %s", track_url, e)
            return None

    # ------------------------------------------------------------------
    # Normalize
    # ------------------------------------------------------------------

    def normalize(self, track_url: str, oembed_data: dict, metadata: dict | None) -> dict:
        """Convert raw data into a SecLens bulletin dict."""
        title = _clean_text(oembed_data.get("title")) or track_url
        description = _clean_text(oembed_data.get("description"))
        author_name = _clean_text(oembed_data.get("author_name"))
        html = oembed_data.get("html")

        # Extract track ID from iframe
        track_id = _extract_track_id_from_iframe(html)

        # Generate external ID
        slug = _slug_from_url(track_url)
        external_id = track_id or slug or track_url

        # Determine published_at
        created_at = metadata.get("created_at") if metadata else None
        published_at = parse_first(
            [(created_at, "metadata.created_at")],
            default_tz="America/New_York",
        )

        # Labels and topics
        labels = []
        if author_name:
            labels.append(f"author:{author_name.lower()}")
        labels.append("media:podcast")
        labels.append("media:audio")

        topics = ["audio-video", "podcast", "conference"]

        # Extract useful metrics from metadata
        play_count = None
        cover_image = None
        if metadata:
            meta_tags = metadata.get("meta", {})
            play_count_str = meta_tags.get("soundcloud:play_count")
            if play_count_str and play_count_str.isdigit():
                play_count = int(play_count_str)
            og_image = meta_tags.get("og:image")
            if og_image and "sndcdn.com" in og_image and "placeholder" not in og_image:
                cover_image = og_image

        extra: dict = {"track_id": track_id}
        if cover_image:
            extra["cover_image"] = cover_image
        if play_count is not None:
            extra["play_count"] = play_count

        return {
            "source": {
                "source_slug": SOURCE_SLUG,
                "external_id": external_id,
                "origin_url": track_url,
                "manifest": MANIFEST,
                "manifest_hash": MANIFEST_HASH,
                "manifest_version": MANIFEST_VERSION,
            },
            "content": {
                "title": title,
                "summary": description,
                "body_text": description,
                "published_at": published_at,
                "language": "en",
            },
            "severity": None,
            "fetched_at": now_utc_iso(),
            "labels": labels,
            "topics": topics,
            "extra": extra,
            "raw": {
                "track_url": track_url,
                "oembed": oembed_data,
                "metadata": metadata,
            },
        }

    def collect(self, limit: int | None = DEFAULT_LIMIT) -> tuple[list[dict], dict]:
        """Collect podcast episodes."""
        try:
            track_links = self.fetch_track_links()
        except requests.RequestException as exc:
            logger.error("Failed to fetch track listing: %s", exc)
            return [], {
                "items_processed": 0,
                "items_created": 0,
                "items_skipped_cache": 0,
            }

        if limit:
            track_links = track_links[:limit]

        bulletins: list[dict] = []
        items_processed = 0
        items_created = 0

        for track_url in track_links:
            items_processed += 1

            # Check cache
            slug = _slug_from_url(track_url)
            if slug and self.cache.is_cached(slug):
                logger.debug("Skipping cached track: %s", slug)
                self.items_skipped_cache += 1
                continue

            # Fetch data
            oembed_data = self.fetch_oembed_data(track_url)
            if not oembed_data:
                logger.warning("Skipping track without oEmbed data: %s", track_url)
                continue

            metadata = self.fetch_track_metadata(track_url)

            # Normalize
            bulletin = self.normalize(track_url, oembed_data, metadata)
            bulletins.append(bulletin)
            items_created += 1

            # Add to cache
            if slug:
                self.cache.add(slug)

        # Save cache
        self.cache.save()

        stats = {
            "items_processed": items_processed,
            "items_created": items_created,
            "items_skipped_cache": self.items_skipped_cache,
        }

        logger.info(
            "Collected %d new episodes (processed: %d, skipped: %d)",
            items_created, items_processed, self.items_skipped_cache,
        )

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

    collector = RSACPodcastCollector()
    bulletins, stats = collector.collect()
    logger.info("Collection stats: %s", stats)

    if not bulletins:
        logger.info("No items to push")
        return

    result = push_to_seclens(bulletins)
    logger.info(
        "Done: created=%d accepted=%s duplicates=%s skipped_cache=%d",
        stats["items_created"],
        result.get("accepted", 0),
        result.get("duplicates", 0),
        stats["items_skipped_cache"],
    )


if __name__ == "__main__":
    main()
