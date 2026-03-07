"""NVIDIA security bulletin collector.

Fetches NVIDIA security bulletins from the official API and pushes them to
a SecLens server. Fully standalone - no SecLens app dependencies.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 1 hour (3600s)
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from bs4 import BeautifulSoup

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
SOURCE_SLUG = "nvidia_security_bulletin"
USER_AGENT = "SeclensCollector/2.0 (nvidia_security_bulletin)"
API_BASE_URL = os.environ.get(
    "NVIDIA_API_URL",
    "https://www.nvidia.com/content/dam/en-zz/Solutions/product-security/product-security.json",
)
REQUEST_TIMEOUT = 30
STATE_FILE_NAME = ".cursor"
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)

DEFAULT_HEADERS = {
    "accept": "application/json, text/javascript, */*; q=0.01",
    "accept-language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "cache-control": "no-cache",
    "pragma": "no-cache",
    "dnt": "1",
    "sec-ch-ua": '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
    "user-agent": USER_AGENT,
    "x-requested-with": "XMLHttpRequest",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean_html_content(html_content: str | None) -> str:
    """Extract clean text from HTML content using BeautifulSoup."""
    if not html_content:
        return ""
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        for script in soup(["script", "style"]):
            script.decompose()
        text = soup.get_text(separator=" ", strip=True)
        return " ".join(text.split())
    except Exception as e:
        logging.warning("Failed to clean HTML content: %s", e)
        return html_content


def _extract_url_from_html_link(html_link: str) -> str | None:
    """Extract URL from HTML anchor tag."""
    try:
        soup = BeautifulSoup(html_link, "html.parser")
        link_tag = soup.find("a")
        if link_tag and link_tag.get("href"):
            return link_tag["href"]
    except Exception as e:
        logger.warning("Failed to extract URL from HTML link: %s", e)
    return None


def _extract_cve_ids(cve_str: str | None) -> list[str]:
    """Extract CVE IDs from a string containing CVE identifiers."""
    if not cve_str:
        return []
    cve_candidates = re.split(r'[,;]', cve_str)
    cve_ids = []
    for cve_candidate in cve_candidates:
        cve_candidate = cve_candidate.strip()
        if cve_candidate.upper().startswith("CVE-"):
            cve_ids.append(cve_candidate.upper())
    return cve_ids


# ---------------------------------------------------------------------------
# State (cursor) helpers
# ---------------------------------------------------------------------------

def _state_path() -> Path:
    return Path(__file__).resolve().with_name(STATE_FILE_NAME)


def load_cursor() -> set[str]:
    """Load previously seen bulletin IDs from state file."""
    try:
        content = _state_path().read_text(encoding="utf-8").strip()
        if content:
            return set(json.loads(content))
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.warning("Invalid cursor file content: %s", e)
    return set()


def save_cursor(bulletin_ids: set[str]) -> None:
    """Save current set of bulletin IDs to state file."""
    try:
        _state_path().write_text(json.dumps(list(bulletin_ids)), encoding="utf-8")
    except Exception as e:
        logger.error("Failed to save cursor file: %s", e)


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

def fetch_list(api_url: str = API_BASE_URL) -> Sequence[dict]:
    """Fetch the list of security bulletins from NVIDIA API."""
    logger.info("Fetching bulletins from: %s", api_url)
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    response = session.get(api_url, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    body = response.json()

    data = body.get("data")
    if isinstance(data, list):
        return data[:10]
    return []


def fetch_github_detail(bulletin_id: str, publish_date: str) -> tuple[str, str] | None:
    """Fetch detailed content from NVIDIA GitHub repository."""
    try:
        date_parts = publish_date.split()
        if len(date_parts) >= 3:
            year = date_parts[2]
        else:
            year = str(datetime.now().year)

        url = f"https://raw.githubusercontent.com/NVIDIA/product-security/main/{year}/{bulletin_id}/{bulletin_id}.md"
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})

        if response.status_code == 200:
            content = response.text
            title_match = re.search(r"^# (.+)", content, re.MULTILINE)
            title = title_match.group(1) if title_match else f"NVIDIA Security Bulletin {bulletin_id}"
            return title, content
    except Exception as e:
        logger.debug("GitHub detail fetch failed for bulletin %s: %s", bulletin_id, e)
    return None


def fetch_custhelp_detail(url: str) -> tuple[str, str] | None:
    """Fetch detailed content from nvidia.custhelp.com."""
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        main_content_div = soup.find("div", id="rn_MainColumn", attrs={"role": "main"})

        if main_content_div:
            content = _clean_html_content(str(main_content_div))
            title_tag = soup.find("title")
            title = title_tag.get_text().strip() if title_tag else "Security Bulletin Details"
            return title, content
    except Exception as e:
        logger.debug("Customer help detail fetch failed for %s: %s", url, e)
    return None


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------

def normalize(item: dict) -> dict:
    """Normalize API response item to a SecLens bulletin dict."""
    fetched_at = now_utc_iso()

    bulletin_id = item.get("bulletin id", "")
    title_html = item.get("title", "")
    severity = item.get("severity", "")
    cve_identifiers = item.get("cve identifier(s)", "")
    publish_date = item.get("publish date", "")
    last_updated = item.get("last updated", "")

    # Extract URL from the title HTML
    origin_url = _extract_url_from_html_link(title_html)

    # Extract actual title from HTML
    try:
        soup = BeautifulSoup(title_html, "html.parser")
        actual_title = soup.get_text().strip()
    except Exception:
        actual_title = title_html.strip()

    # Parse publication time
    published_at = parse_first(
        [
            (publish_date, "item.publish_date"),
            (last_updated, "item.last_updated"),
        ],
        default_tz="UTC",
    )

    # Parse CVE IDs
    cve_ids = _extract_cve_ids(cve_identifiers)

    # Get detailed content from GitHub first, fallback to custhelp
    detail_title = ""
    detail_content = ""

    if bulletin_id:
        github_detail = fetch_github_detail(bulletin_id, publish_date)
        if github_detail:
            detail_title, detail_content = github_detail
        elif origin_url:
            custhelp_detail = fetch_custhelp_detail(origin_url)
            if custhelp_detail:
                detail_title, detail_content = custhelp_detail

    final_title = detail_title if detail_title else actual_title
    clean_content = _clean_html_content(detail_content)

    # Determine severity level
    severity_level = None
    if severity:
        severity_lower = severity.lower()
        if "critical" in severity_lower:
            severity_level = "critical"
        elif "high" in severity_lower:
            severity_level = "high"
        elif "medium" in severity_lower or "moderate" in severity_lower:
            severity_level = "medium"
        elif "low" in severity_lower:
            severity_level = "low"

    labels: list[str] = []
    if bulletin_id:
        labels.append(f"bulletin_id:{bulletin_id}")
    if cve_ids:
        labels.extend([f"cve:{cve_id}" for cve_id in cve_ids])

    topics = ["official_bulletin"]
    if cve_ids:
        topics.append("cve")

    extra: dict[str, Any] = {
        "bulletin_id": bulletin_id,
        "severity_raw": severity,
        "cve_identifiers_raw": cve_identifiers,
        "publish_date_raw": publish_date,
        "last_updated_raw": last_updated,
        "title_html": title_html,
        "origin_url": origin_url,
    }

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": bulletin_id,
            "origin_url": origin_url,
            "manifest": MANIFEST,
            "manifest_hash": MANIFEST_HASH,
            "manifest_version": MANIFEST_VERSION,
        },
        "content": {
            "title": final_title,
            "summary": clean_content[:500] if clean_content else actual_title,
            "body_text": clean_content,
            "published_at": published_at,
            "language": "en",
        },
        "severity": severity_level,
        "fetched_at": fetched_at,
        "labels": labels,
        "topics": topics,
        "extra": extra,
        "raw": dict(item),
    }


# ---------------------------------------------------------------------------
# Collect
# ---------------------------------------------------------------------------

def collect() -> tuple[list[dict], dict]:
    """Collect and normalize NVIDIA security bulletins."""
    items = fetch_list()

    # Load previously seen bulletin IDs
    seen_ids = load_cursor()

    # Filter out already seen bulletins
    new_items = [item for item in items if item.get("bulletin id", "") not in seen_ids]
    logger.info("Total items: %d, New items: %d, Skipped: %d", len(items), len(new_items), len(items) - len(new_items))

    # Process new items
    bulletins: list[dict] = []
    new_ids: set[str] = set()

    for item in new_items:
        try:
            bulletin = normalize(item)
            bulletins.append(bulletin)
            new_ids.add(item.get("bulletin id", ""))
        except Exception as e:
            logger.error("Failed to normalize bulletin: %s", e)

    # Add new IDs to seen set and save
    all_seen_ids = seen_ids.union(new_ids)
    save_cursor(all_seen_ids)

    stats = {
        "items_processed": len(items),
        "items_created": len(bulletins),
        "items_skipped_cache": len(items) - len(new_items),
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
