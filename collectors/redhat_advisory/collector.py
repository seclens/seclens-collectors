"""Red Hat Security Advisory collector.

Fetches security advisories from the Red Hat Hydra API and pushes them
to a SecLens server. Fully standalone - no SecLens app dependencies.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 1 hour (3600s)
"""
from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Sequence

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.time_helpers import parse_first, now_utc_iso

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")
SOURCE_SLUG = "redhat_advisory"
USER_AGENT = "SeclensCollector/2.0 (redhat_advisory)"
REQUEST_TIMEOUT = 30

API_URL = "https://access.redhat.com/hydra/rest/search/kcs"
DEFAULT_ROWS = 20
BASE_QUERY_PARAMS = {
    "q": "*:*",
    "q.orig": "*:*",
    "defType": "edismax",
    "rows": str(DEFAULT_ROWS),
    "start": "0",
    "sort": "portal_update_date desc",
    "hl": "true",
    "hl.fl": "lab_description",
    "hl.simple.pre": "%3Cmark%3E",
    "hl.simple.post": "%3C%2Fmark%3E",
    "facet": "true",
    "facet.mincount": "1",
    "facet.field": ["portal_severity", "portal_advisory_type"],
    "fq": [
        'portal_advisory_type:("Security Advisory") AND documentKind:("Errata")',
        "-documentKind:( ApplicationAttribute )",
        "-accessState:(private OR retired) AND -hasPublishedRevision:false",
        "-doNotDisplay:true",
        "-catalog_visibility:hidden",
        "-documentKind:( ProductLifeCycle )",
        "-archived:true",
    ],
    "fl": "id,portal_severity,portal_product_names,portal_CVE,portal_publication_date,portal_synopsis,view_uri,allTitle,portal_update_date",
}

ARTICLE_SELECTOR = "main#cp-main.portal-content-area"
ARTICLE_ACCEPT = "text/html,application/xhtml+xml"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


@dataclass
class FetchParams:
    """Parameters controlling Red Hat advisory API queries."""
    start: int = 0
    rows: int = DEFAULT_ROWS


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


def fetch_advisories(params: FetchParams | None = None) -> list[dict]:
    """Fetch advisories from the Red Hat Hydra API."""
    params = params or FetchParams()
    logger.info("Fetching Red Hat advisories (start=%d, rows=%d)", params.start, params.rows)

    payload = dict(BASE_QUERY_PARAMS)
    payload["start"] = str(params.start)
    payload["rows"] = str(params.rows)

    session = requests.Session()
    session.headers.update(
        {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            "Referer": "https://access.redhat.com/security/security-updates/security-advisories",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }
    )

    response = session.get(API_URL, params=payload, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    data = response.json()
    docs = data.get("response", {}).get("docs", [])
    if not isinstance(docs, Iterable):
        logger.warning("Unexpected Red Hat payload: %s", data)
        return []
    logger.info("Fetched %d advisories", len(docs))
    return list(docs)


def _fetch_article_body(url: str | None) -> str | None:
    """Fetch the full article body from a Red Hat advisory page."""
    if not url:
        return None
    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={
                "Accept": ARTICLE_ACCEPT,
                "User-Agent": USER_AGENT,
            },
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.debug("Failed to fetch Red Hat advisory body %s: %s", url, exc)
        return None
    soup = BeautifulSoup(resp.text, "html.parser")
    container = soup.select_one(ARTICLE_SELECTOR) or soup.select_one("main") or soup.body
    if not container:
        return None
    text_parts: list[str] = []
    seen: set[str] = set()
    for element in container.find_all(["p", "li"]):
        text = " ".join(element.stripped_strings)
        if not text:
            continue
        if text.lower() in {"skip to content", "skip to main content"}:
            continue
        if text in seen:
            continue
        seen.add(text)
        text_parts.append(text)
    if text_parts:
        return "\n\n".join(text_parts)
    fallback = container.get_text("\n", strip=True)
    return fallback or None


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(item: dict) -> dict:
    """Convert a Red Hat advisory doc to a SecLens bulletin dict."""
    external_id = str(item.get("id")) if item.get("id") else None
    origin_url = item.get("view_uri")
    fetched_at = now_utc_iso()

    published_at = parse_first(
        [(item.get("portal_publication_date"), "item.portal_publication_date")],
        default_tz="UTC",
    )

    severity = item.get("portal_severity")
    summary = item.get("portal_synopsis") or item.get("allTitle")
    body_text = _fetch_article_body(origin_url)
    if not summary and body_text:
        summary = body_text.splitlines()[0][:240]

    labels: list[str] = []
    if severity:
        labels.append(severity)
    products = item.get("portal_product_names") or []
    if isinstance(products, list):
        labels.extend(str(product) for product in products if product)

    topics = ["official_advisory", "redhat"]

    extra: dict[str, object] = {
        "cves": item.get("portal_CVE"),
        "product_names": products,
        "update_date": item.get("portal_update_date"),
    }

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": external_id,
            "origin_url": origin_url,
        },
        "content": {
            "title": item.get("allTitle") or summary or (external_id or ""),
            "summary": summary,
            "body_text": body_text,
            "published_at": published_at,
        },
        "severity": severity,
        "fetched_at": fetched_at,
        "labels": labels,
        "topics": topics,
        "extra": {k: v for k, v in extra.items() if v},
        "raw": item,
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

    docs = fetch_advisories()
    bulletins: list[dict] = []
    for doc in docs:
        try:
            bulletins.append(normalize(doc))
        except Exception as exc:
            logger.exception("Failed to normalize Red Hat advisory %s", doc, exc_info=exc)

    if not bulletins:
        logger.info("No items to push")
        return

    result = push_to_seclens(bulletins)
    print(
        f"Done: {len(bulletins)} fetched, "
        f"{result.get('accepted', 0)} accepted, "
        f"{result.get('duplicates', 0)} duplicates"
    )


if __name__ == "__main__":
    main()
