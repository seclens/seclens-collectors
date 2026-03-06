"""CCGP central government procurement collector - standalone version.

Scrapes central government procurement announcements from CCGP (China Government
Procurement Network), filters by security-related keywords, and pushes to
a SecLens server. Reuses the shared logic from ccgp_local_procurement.

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

import requests

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.time_helpers import now_utc_iso

# Reuse the shared CCGP logic from the local procurement collector
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ccgp_local_procurement.collector import (
    DEFAULT_CENTRAL_LIST_URL,
    fetch_list,
    normalize as _normalize_local,
    push_to_seclens as _push_base,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")

SOURCE_SLUG = "ccgp_central_procurement"
USER_AGENT = "SeclensCollector/2.0 (ccgp_central_procurement)"
REQUEST_TIMEOUT = 30

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


# ---------------------------------------------------------------------------
# Normalize (override slug and topics)
# ---------------------------------------------------------------------------


def normalize(item: dict) -> dict | None:
    """Normalize using shared CCGP logic but with central procurement slug."""
    return _normalize_local(
        item,
        source_slug=SOURCE_SLUG,
        topics=["security_procurement"],
    )


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

    list_url = os.environ.get("CCGP_LIST_URL", DEFAULT_CENTRAL_LIST_URL)
    items = fetch_list(list_url=list_url)

    bulletins = []
    for item in items:
        try:
            bulletin = normalize(item)
        except requests.RequestException:
            continue
        if bulletin:
            bulletins.append(bulletin)

    if not bulletins:
        logger.info("No security-related items to push")
        return

    result = push_to_seclens(bulletins)
    print(
        f"Done: {len(bulletins)} fetched, "
        f"{result.get('accepted', 0)} accepted, "
        f"{result.get('duplicates', 0)} duplicates"
    )


if __name__ == "__main__":
    main()
