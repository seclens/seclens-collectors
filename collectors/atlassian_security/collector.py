"""Atlassian Security Advisories Collector (standalone).

Fetches vulnerability information from Atlassian's public API and optionally
fetches additional details from their JIRA issue tracking system.

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
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.time_helpers import parse_first, now_utc_iso

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")

SOURCE_SLUG = "atlassian_security"
USER_AGENT = "SeclensCollector/2.0 (atlassian_security)"
STATE_FILE_NAME = ".cursor"
MAX_CACHE_SIZE = 100
DEFAULT_DAYS_FILTER = 30
DEFAULT_API_URL = "https://www.atlassian.com/gateway/api/vuln-transparency/v1/products"
REQUEST_TIMEOUT = 30

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
LOGGER = logging.getLogger(SOURCE_SLUG)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def parse_atlassian_date(date_str: str) -> Optional[datetime]:
    """Parse Atlassian date string to datetime object."""
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except ValueError:
        try:
            dt = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S.000+0000')
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            LOGGER.warning(f"Could not parse date: {date_str}")
            return None


def clean_html_content(content: str) -> str:
    """Clean HTML content by removing extra whitespace and formatting."""
    if not content:
        return content
    cleaned = re.sub(r'\s+', ' ', content)
    return cleaned.strip()


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class AtlassianSecurityCollector:
    """Handle fetching and normalizing Atlassian security advisories."""

    def __init__(
        self,
        *,
        session: requests.Session | None = None,
        api_url: str | None = None,
        state_path: Path | None = None,
        days_filter: int = DEFAULT_DAYS_FILTER,
    ) -> None:
        self.session = session or requests.Session()
        self.api_url = api_url or DEFAULT_API_URL
        self.state_path = state_path or Path(__file__).resolve().with_name(STATE_FILE_NAME)
        self.days_filter = days_filter
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
        })

    # --- Cache helpers --------------------------------------------------
    def load_cache(self) -> set[str]:
        """Load cached CVE IDs from JSON file."""
        try:
            with self.state_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    items = data.get("cve_ids", [])
                    if isinstance(items, list):
                        return set(items)
            return set()
        except (FileNotFoundError, json.JSONDecodeError):
            return set()

    def save_cache(self, cve_ids: set[str]) -> None:
        """Save CVE IDs to cache, keeping only the latest MAX_CACHE_SIZE items."""
        ids_list = list(cve_ids)[-MAX_CACHE_SIZE:]
        with self.state_path.open("w", encoding="utf-8") as f:
            json.dump(
                {
                    "cve_ids": ids_list,
                    "updated_at": now_utc_iso(),
                },
                f,
                indent=2,
                ensure_ascii=False,
            )

    # --- Fetch ----------------------------------------------------------
    def fetch_api_data(self) -> Dict[str, Any]:
        """Fetch security data from Atlassian's API."""
        LOGGER.info(f"Fetching Atlassian security data from {self.api_url}")

        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self.session.get(self.api_url, timeout=60)
                response.raise_for_status()
                LOGGER.info(f"Successfully fetched data, status code: {response.status_code}")
                return response.json()
            except requests.RequestException as e:
                LOGGER.error(f"Attempt {attempt + 1}/{max_retries} failed: {e}")
                if attempt == max_retries - 1:
                    LOGGER.error(f"Failed to fetch data after {max_retries} attempts")
                    raise
            except json.JSONDecodeError as e:
                LOGGER.error(f"Failed to parse JSON response: {e}")
                raise ValueError("Invalid JSON response from Atlassian API") from e

        return {}

    def fetch_jira_details(self, url: str) -> Optional[str]:
        """Fetch additional details from JIRA issue page."""
        try:
            headers = {
                'User-Agent': USER_AGENT,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            }

            response = self.session.get(url, headers=headers, timeout=10)
            response.raise_for_status()

            soup = BeautifulSoup(response.content, 'html.parser')

            details_module = soup.find('div', id='details-module')
            if details_module:
                text_content = details_module.get_text(separator=' ', strip=True)
                return clean_html_content(text_content)

            issue_container = soup.find('div', class_='issue-container')
            if issue_container:
                text_content = issue_container.get_text(separator=' ', strip=True)
                return clean_html_content(text_content)

            LOGGER.warning(f"No details found in JIRA page: {url}")
            return None

        except Exception as e:
            LOGGER.warning(f"Failed to fetch JIRA details from {url}: {e}")
            return None

    # --- Extract --------------------------------------------------------
    def extract_cve_details(self, json_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract CVE details from the API JSON response."""
        cve_list = []
        cve_metadata = json_data.get('cve_metadata', {})

        cve_to_products = {}
        all_products = json_data.get('products', {})
        for product_name, product_info in all_products.items():
            for version, cve_list_for_version in product_info.get('versions', {}).items():
                for cve_item in cve_list_for_version:
                    if isinstance(cve_item, dict):
                        for item_cve_id, status in cve_item.items():
                            if item_cve_id not in cve_to_products:
                                cve_to_products[item_cve_id] = []
                            cve_to_products[item_cve_id].append({
                                'product': product_name,
                                'version': version,
                                'status': status
                            })

        for cve_id, cve_info in cve_metadata.items():
            if not cve_info:
                continue

            cve_details = {
                'cve_id': cve_id,
                'summary': cve_info.get('cve_summary', ''),
                'description': cve_info.get('cve_description', ''),
                'publish_date': parse_atlassian_date(cve_info.get('cve_publish_date', '')),
                'severity': cve_info.get('cve_severity', ''),
                'tracking_url': cve_info.get('atl_tracking_url', ''),
                'affected_products': cve_to_products.get(cve_id, [])
            }
            cve_list.append(cve_details)

        return cve_list

    def filter_recent_cves(self, cve_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter CVEs published within the configured time window."""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.days_filter)
        recent_cves = []

        for cve in cve_list:
            publish_date = cve.get('publish_date')
            if publish_date:
                if publish_date.tzinfo is None:
                    publish_date = publish_date.replace(tzinfo=timezone.utc)
                if publish_date >= cutoff_date:
                    recent_cves.append(cve)

        return recent_cves

    # --- Normalize ------------------------------------------------------
    def normalize(self, cve_info: Dict[str, Any], fetch_jira: bool = True) -> dict:
        """Create a bulletin dict from CVE information."""
        description = cve_info.get('description', '')

        tracking_url = cve_info.get('tracking_url', '')
        if fetch_jira and tracking_url:
            additional_details = self.fetch_jira_details(tracking_url)
            if additional_details:
                description += f"\n\nAdditional details: {additional_details}"

        affected_products = cve_info.get('affected_products', [])
        if affected_products:
            product_info = "\n\nAffected products:\n"
            for product in affected_products:
                product_info += f"- {product.get('product', '')} {product.get('version', '')} ({product.get('status', '')})\n"
            description += product_info

        cve_id = cve_info.get('cve_id')
        if not cve_id:
            raise ValueError("Missing CVE ID")

        title = cve_info.get('summary', '').strip() or cve_id

        labels = ["atlassian", "security", "cve"]
        labels.extend([
            p['product'].replace(" ", "_").lower()
            for p in affected_products if p.get('product')
        ])

        fetched_at = now_utc_iso()

        # Use parse_first for published_at
        publish_date = cve_info.get('publish_date')
        published_at = parse_first(
            [(publish_date, "publish_date")],
            default_tz="UTC",
        )

        return {
            "source": {
                "source_slug": SOURCE_SLUG,
                "external_id": cve_id,
                "origin_url": tracking_url or None,
            },
            "content": {
                "title": title,
                "summary": title,
                "body_text": description,
                "published_at": published_at,
                "language": "en",
            },
            "severity": str(cve_info.get('severity', '')),
            "fetched_at": fetched_at,
            "labels": labels,
            "extra": {
                "cve_id": cve_id,
                "tracking_url": tracking_url,
                "affected_products": affected_products,
            },
            "raw": cve_info,
        }

    # --- Collection -----------------------------------------------------
    def collect(
        self,
        *,
        force: bool = False,
        fetch_jira: bool = True,
    ) -> tuple[list[dict], dict]:
        """Collect bulletins from Atlassian Security API."""
        LOGGER.info("=" * 60)
        LOGGER.info("Starting Atlassian Security collection")
        LOGGER.info("=" * 60)

        cached_ids = set() if force else self.load_cache()
        LOGGER.info(f"Loaded cache: {len(cached_ids)} CVE IDs already seen")

        json_data = self.fetch_api_data()
        all_cves = self.extract_cve_details(json_data)
        LOGGER.info(f"Extracted {len(all_cves)} total CVEs from API")

        recent_cves = self.filter_recent_cves(all_cves)
        LOGGER.info(f"Filtered to {len(recent_cves)} recent CVEs (last {self.days_filter} days)")

        new_cves: List[Dict[str, Any]] = []
        skipped_count = 0
        for cve in recent_cves:
            cve_id = cve.get('cve_id')
            if cve_id in cached_ids:
                skipped_count += 1
                continue
            new_cves.append(cve)

        LOGGER.info(f"Filtering results:")
        LOGGER.info(f"  - New CVEs to process: {len(new_cves)}")
        LOGGER.info(f"  - Skipped (already cached): {skipped_count}")

        LOGGER.info(f"Normalizing {len(new_cves)} CVEs to bulletins...")
        bulletins: list[dict] = []
        for i, cve in enumerate(new_cves, 1):
            try:
                bulletin = self.normalize(cve, fetch_jira=fetch_jira)
                bulletins.append(bulletin)
                LOGGER.info(f"  [{i}/{len(new_cves)}] {cve.get('cve_id')}: {cve.get('summary', '')[:60]}...")
            except Exception as e:
                LOGGER.error(f"  [{i}/{len(new_cves)}] Failed to normalize {cve.get('cve_id')}: {e}")

        if bulletins and not force:
            new_ids = {cve.get('cve_id') for cve in new_cves if cve.get('cve_id')}
            updated_cache = cached_ids | new_ids
            self.save_cache(updated_cache)
            LOGGER.info(f"Cache updated: {len(updated_cache)} total CVE IDs")

        stats = {
            "items_processed": len(recent_cves),
            "items_created": len(bulletins),
            "items_skipped_cache": skipped_count,
        }

        LOGGER.info("=" * 60)
        LOGGER.info("Collection summary:")
        LOGGER.info(f"  - Total items from API: {stats['items_processed']}")
        LOGGER.info(f"  - Items created: {stats['items_created']}")
        LOGGER.info(f"  - Items skipped (cached): {stats['items_skipped_cache']}")
        LOGGER.info("=" * 60)

        return bulletins, stats


# ---------------------------------------------------------------------------
# Push
# ---------------------------------------------------------------------------


def push_to_seclens(bulletins: list[dict]) -> dict:
    """Submit bulletins to the SecLens Ingest API."""
    endpoint = f"{SECLENS_URL}/v1/ingest/bulletins"
    LOGGER.info("Pushing %d bulletins to %s", len(bulletins), endpoint)

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
    LOGGER.info(
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
        LOGGER.error("SECLENS_URL environment variable is required")
        sys.exit(1)
    if not SECLENS_TOKEN:
        LOGGER.error("SECLENS_TOKEN environment variable is required")
        sys.exit(1)

    collector = AtlassianSecurityCollector()
    bulletins, stats = collector.collect()

    if not bulletins:
        LOGGER.info("No new bulletins to push")
        return

    result = push_to_seclens(bulletins)
    print(
        f"Done: {stats['items_created']} created, "
        f"{result.get('accepted', 0)} accepted, "
        f"{result.get('duplicates', 0)} duplicates"
    )


if __name__ == "__main__":
    main()
