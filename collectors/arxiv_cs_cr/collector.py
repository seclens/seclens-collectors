"""arXiv Computer Science > Cryptography and Security collector.

Fetches recent papers from the arXiv API for category cs.CR and pushes them
to a SecLens server.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 24 hours (86400s)
"""
from __future__ import annotations

import logging
import os
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

try:
    from shared.manifest import load_manifest_for_slug
    from shared.time_helpers import now_utc_iso, parse_datetime
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from shared.manifest import load_manifest_for_slug
    from shared.time_helpers import now_utc_iso, parse_datetime


SOURCE_SLUG = "arxiv_cs_cr"
SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")

API_URL = os.environ.get("ARXIV_API_URL", "https://export.arxiv.org/api/query")
SEARCH_QUERY = os.environ.get("ARXIV_SEARCH_QUERY", "cat:cs.CR")
MAX_RESULTS = int(os.environ.get("ARXIV_MAX_RESULTS", "50"))
SORT_BY = os.environ.get("ARXIV_SORT_BY", "submittedDate")
SORT_ORDER = os.environ.get("ARXIV_SORT_ORDER", "descending")
REQUEST_TIMEOUT = int(os.environ.get("ARXIV_REQUEST_TIMEOUT", "45"))
PUSH_BATCH_SIZE = int(os.environ.get("ARXIV_PUSH_BATCH_SIZE", "50"))
REQUEST_DELAY_SECONDS = float(os.environ.get("ARXIV_REQUEST_DELAY_SECONDS", "3"))
USER_AGENT = "SeclensCollector/2.0 (arxiv_cs_cr; https://seclens.info)"

ATOM_NS = "http://www.w3.org/2005/Atom"
ARXIV_NS = "http://arxiv.org/schemas/atom"
NS = {"atom": ATOM_NS, "arxiv": ARXIV_NS}

MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(
    SOURCE_SLUG,
    repo_root=Path(__file__).resolve().parents[2],
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


def _trim(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = " ".join(value.split()).strip()
    return cleaned or None


def _entry_text(entry: ET.Element, path: str) -> str | None:
    return _trim(entry.findtext(path, namespaces=NS))


def _normalise_arxiv_url(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip()
    if text.startswith("http://arxiv.org/"):
        text = "https://arxiv.org/" + text[len("http://arxiv.org/") :]
    return text


def _arxiv_id_from_url(value: str | None) -> str | None:
    if not value:
        return None
    path = urlparse(value).path.rstrip("/")
    if not path:
        return None
    return path.rsplit("/", 1)[-1] or None


def _extract_links(entry: ET.Element) -> tuple[str | None, str | None]:
    origin_url = None
    pdf_url = None

    for link in entry.findall("atom:link", NS):
        href = _normalise_arxiv_url(link.attrib.get("href"))
        rel = (link.attrib.get("rel") or "").lower()
        link_type = (link.attrib.get("type") or "").lower()
        title = (link.attrib.get("title") or "").lower()

        if href and rel == "alternate":
            origin_url = href
        if href and (link_type == "application/pdf" or title == "pdf"):
            pdf_url = href

    return origin_url, pdf_url


def _extract_doi(entry: ET.Element) -> str | None:
    doi = _entry_text(entry, "arxiv:doi")
    if doi:
        return doi

    for link in entry.findall("atom:link", NS):
        title = (link.attrib.get("title") or "").lower()
        href = link.attrib.get("href") or ""
        if title == "doi" and "doi.org/" in href:
            return href.rsplit("doi.org/", 1)[-1].strip() or None
    return None


def _extract_authors(entry: ET.Element) -> list[str]:
    authors: list[str] = []
    for author in entry.findall("atom:author", NS):
        name = _trim(author.findtext("atom:name", namespaces=NS))
        if name:
            authors.append(name)
    return authors


def _extract_categories(entry: ET.Element) -> tuple[list[str], str | None]:
    categories: list[str] = []
    for category in entry.findall("atom:category", NS):
        term = _trim(category.attrib.get("term"))
        if term:
            categories.append(term)

    primary_node = entry.find("arxiv:primary_category", NS)
    primary = _trim(primary_node.attrib.get("term")) if primary_node is not None else None
    return categories, primary


def fetch_entries() -> list[ET.Element]:
    """Fetch recent cs.CR papers from the arXiv API."""
    params = {
        "search_query": SEARCH_QUERY,
        "sortBy": SORT_BY,
        "sortOrder": SORT_ORDER,
        "start": 0,
        "max_results": MAX_RESULTS,
    }
    logger.info("Fetching arXiv API: %s", params)
    response = requests.get(
        API_URL,
        params=params,
        timeout=REQUEST_TIMEOUT,
        headers={
            "Accept": "application/atom+xml, application/xml;q=0.9, */*;q=0.8",
            "User-Agent": USER_AGENT,
        },
    )
    response.raise_for_status()

    root = ET.fromstring(response.content)
    entries = root.findall("atom:entry", NS)
    logger.info("Fetched %d arXiv entries", len(entries))
    if REQUEST_DELAY_SECONDS > 0:
        time.sleep(REQUEST_DELAY_SECONDS)
    return entries


def normalize(entry: ET.Element) -> dict[str, Any]:
    """Convert an arXiv Atom entry to SecLens bulletin dict."""
    entry_id = _normalise_arxiv_url(_entry_text(entry, "atom:id"))
    origin_url, pdf_url = _extract_links(entry)
    origin_url = origin_url or entry_id
    arxiv_id = _arxiv_id_from_url(origin_url or entry_id)

    title = _entry_text(entry, "atom:title") or arxiv_id or "arXiv cs.CR paper"
    summary = _entry_text(entry, "atom:summary")
    published_at = parse_datetime(_entry_text(entry, "atom:published"), default_tz="UTC")
    updated_at = parse_datetime(_entry_text(entry, "atom:updated"), default_tz="UTC")
    authors = _extract_authors(entry)
    categories, primary_category = _extract_categories(entry)
    doi = _extract_doi(entry)
    comment = _entry_text(entry, "arxiv:comment")

    body_lines = []
    if summary:
        body_lines.append(summary)
    if authors:
        body_lines.append("Authors: " + ", ".join(authors))
    if categories:
        body_lines.append("Categories: " + ", ".join(categories))
    if pdf_url:
        body_lines.append("PDF: " + pdf_url)
    if doi:
        body_lines.append("DOI: " + doi)
    if comment:
        body_lines.append("Comment: " + comment)

    labels = ["source:arxiv", "type:paper", "category:cs.cr"]
    for category in categories:
        labels.append(f"category:{category.lower()}")
    if primary_category:
        labels.append(f"primary_category:{primary_category.lower()}")
    if doi:
        labels.append("has_doi")

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": arxiv_id or entry_id or title,
            "origin_url": origin_url,
            "manifest": MANIFEST,
            "manifest_hash": MANIFEST_HASH,
            "manifest_version": MANIFEST_VERSION,
        },
        "content": {
            "title": title,
            "summary": summary,
            "body_text": "\n\n".join(body_lines) if body_lines else None,
            "published_at": published_at,
            "language": "en",
        },
        "fetched_at": now_utc_iso(),
        "labels": sorted({label for label in labels if label}),
        "topics": ["research", "security-research"],
        "extra": {
            "arxiv_id": arxiv_id,
            "entry_id": entry_id,
            "authors": authors,
            "categories": categories,
            "primary_category": primary_category,
            "pdf_url": pdf_url,
            "doi": doi,
            "comment": comment,
            "updated_at": updated_at,
            "search_query": SEARCH_QUERY,
        },
        "raw": {
            "id": entry_id,
            "title": title,
            "summary": summary,
            "published": _entry_text(entry, "atom:published"),
            "updated": _entry_text(entry, "atom:updated"),
            "authors": authors,
            "categories": categories,
            "primary_category": primary_category,
            "pdf_url": pdf_url,
            "doi": doi,
            "comment": comment,
        },
    }


def push(bulletins: list[dict[str, Any]]) -> dict[str, int]:
    endpoint = f"{SECLENS_URL}/v1/ingest/bulletins"
    headers = {
        "Authorization": f"Bearer {SECLENS_TOKEN}",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    accepted = 0
    duplicates = 0

    for i in range(0, len(bulletins), PUSH_BATCH_SIZE):
        batch = bulletins[i : i + PUSH_BATCH_SIZE]
        response = requests.post(
            endpoint,
            json=batch,
            timeout=REQUEST_TIMEOUT,
            headers=headers,
        )
        if response.status_code >= 400:
            logger.error(
                "Push failed for batch %s-%s: %s %s",
                i,
                i + len(batch),
                response.status_code,
                response.text[:400],
            )
            response.raise_for_status()
        payload = response.json()
        accepted += int(payload.get("accepted", 0) or 0)
        duplicates += int(payload.get("duplicates", 0) or 0)

    return {"accepted": accepted, "duplicates": duplicates}


def main() -> None:
    if not SECLENS_URL or not SECLENS_TOKEN:
        raise SystemExit("SECLENS_URL and SECLENS_TOKEN are required")

    entries = fetch_entries()
    bulletins = [normalize(entry) for entry in entries]
    if not bulletins:
        logger.info("No arXiv entries to push")
        return

    result = push(bulletins)
    logger.info(
        "Done: fetched=%d accepted=%s duplicates=%s",
        len(bulletins),
        result.get("accepted"),
        result.get("duplicates"),
    )


if __name__ == "__main__":
    main()
