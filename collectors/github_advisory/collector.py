"""GitHub Advisory Database collector.

Fetches security advisories from the GitHub Advisory Database API and pushes
them to a SecLens server. Fully standalone - no SecLens app dependencies.

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
from dataclasses import dataclass
from datetime import datetime, timezone
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
SOURCE_SLUG = "github_advisory"
USER_AGENT = "SeclensCollector/2.0 (github_advisory)"
REQUEST_TIMEOUT = 30
DEFAULT_LIMIT = 30  # Default items per collection run
CACHE_FILE_NAME = ".cursor"
MAX_CACHE_SIZE = 200  # Cache the latest 200 GHSA IDs
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------


@dataclass
class Advisory:
    """Represents a GitHub Advisory."""
    ghsa_id: str
    cve_id: str | None
    url: str
    html_url: str
    summary: str
    description: str | None
    severity: str
    cvss_score: float | None
    cvss_vector: str | None
    published_at: str
    updated_at: str
    withdrawn_at: str | None
    package_name: str | None
    package_ecosystem: str | None
    vulnerable_version_range: str | None
    first_patched_version: str | None
    cwe_ids: list[str]
    cwe_names: list[str]
    references: list[str]
    credits: list[dict]
    advisory_type: str
    source_code_location: str | None
    fetched_at: datetime
    raw: dict


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class GitHubAdvisoryCollector:
    """Encapsulates fetch, normalize, and cache persistence for GitHub Advisories."""

    def __init__(
        self,
        *,
        session: requests.Session | None = None,
        api_url: str | None = None,
        cache_path: Path | None = None,
    ) -> None:
        self.session = session or requests.Session()
        self.api_url = api_url or "https://api.github.com/advisories"
        self.cache_path = cache_path or Path(__file__).resolve().with_name(CACHE_FILE_NAME)
        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )

    # --- Cache helpers --------------------------------------------------
    def load_cache(self) -> set[str]:
        """Load cached GHSA IDs from JSON file."""
        try:
            with self.cache_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    items = data.get("ghsa_ids", [])
                    if isinstance(items, list):
                        return set(items)
            return set()
        except (FileNotFoundError, json.JSONDecodeError):
            return set()

    def save_cache(self, ghsa_ids: set[str]) -> None:
        """Save GHSA IDs to cache, keeping only the latest MAX_CACHE_SIZE items."""
        ids_list = list(ghsa_ids)[-MAX_CACHE_SIZE:]
        with self.cache_path.open("w", encoding="utf-8") as f:
            json.dump({"ghsa_ids": ids_list, "updated_at": datetime.now(timezone.utc).isoformat()}, f, indent=2)  # noqa: UP017

    # --- Fetch ----------------------------------------------------------
    def fetch_advisories(self, per_page: int = 30, max_pages: int = 3) -> list[Advisory]:
        """
        Fetch advisories from GitHub API using cursor-based pagination.

        GitHub API uses Link header with cursor parameter for pagination.
        """
        advisories: list[Advisory] = []
        url = self.api_url
        params = {
            "per_page": min(per_page, 100),  # GitHub max is 100
            "sort": "published",
            "direction": "desc",
        }

        fetched_at = datetime.now(timezone.utc)  # noqa: UP017
        page_count = 0

        while url and page_count < max_pages:
            try:
                response = self.session.get(url, params=params if page_count == 0 else None, timeout=REQUEST_TIMEOUT)
                response.raise_for_status()

                # Check rate limit
                remaining = response.headers.get("X-RateLimit-Remaining")
                if remaining and int(remaining) < 10:
                    logger.warning("GitHub API rate limit low: %s requests remaining", remaining)

                data = response.json()
                if not isinstance(data, list):
                    logger.error("Unexpected API response format: %s", type(data))
                    break

                logger.info("Fetched page %d: %d advisories", page_count + 1, len(data))

                for item in data:
                    advisory = self._parse_advisory(item, fetched_at)
                    if advisory:
                        advisories.append(advisory)

                # Parse Link header for next page
                link_header = response.headers.get("Link", "")
                next_url = self._extract_next_url(link_header)

                if not next_url:
                    break

                url = next_url
                params = None  # Next URL already contains all params
                page_count += 1

            except requests.RequestException as e:
                logger.error("Failed to fetch advisories: %s", e)
                break

        logger.info("Total advisories fetched: %d", len(advisories))
        return advisories

    def _parse_advisory(self, item: dict, fetched_at: datetime) -> Advisory | None:
        """Parse a single advisory from API response."""
        try:
            # Extract vulnerability info
            vulnerabilities = item.get("vulnerabilities", [])
            vuln = vulnerabilities[0] if vulnerabilities else {}

            package_info = vuln.get("package", {}) if isinstance(vuln, dict) else {}
            package_name = package_info.get("name") if isinstance(package_info, dict) else None
            package_ecosystem = package_info.get("ecosystem") if isinstance(package_info, dict) else None

            vulnerable_version_range = vuln.get("vulnerable_version_range") if isinstance(vuln, dict) else None
            first_patched_version = vuln.get("first_patched_version") if isinstance(vuln, dict) else None

            # Extract CWE info
            cwes = item.get("cwes", [])
            cwe_ids = [cwe.get("cwe_id") for cwe in cwes if isinstance(cwe, dict) and cwe.get("cwe_id")]
            cwe_names = [cwe.get("name") for cwe in cwes if isinstance(cwe, dict) and cwe.get("name")]

            # Extract CVSS info
            cvss = item.get("cvss", {})
            cvss_score = cvss.get("score") if isinstance(cvss, dict) else None
            cvss_vector = cvss.get("vector_string") if isinstance(cvss, dict) else None

            # Extract credits
            credits_raw = item.get("credits", [])
            credits_info = [
                {
                    "login": credit.get("user", {}).get("login"),
                    "type": credit.get("type"),
                }
                for credit in credits_raw
                if isinstance(credit, dict)
            ]

            # References
            references = item.get("references", [])
            if not isinstance(references, list):
                references = []

            return Advisory(
                ghsa_id=item.get("ghsa_id", ""),
                cve_id=item.get("cve_id"),
                url=item.get("url", ""),
                html_url=item.get("html_url", ""),
                summary=item.get("summary", ""),
                description=item.get("description"),
                severity=item.get("severity", "unknown"),
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                published_at=item.get("published_at", ""),
                updated_at=item.get("updated_at", ""),
                withdrawn_at=item.get("withdrawn_at"),
                package_name=package_name,
                package_ecosystem=package_ecosystem,
                vulnerable_version_range=vulnerable_version_range,
                first_patched_version=first_patched_version,
                cwe_ids=cwe_ids,
                cwe_names=cwe_names,
                references=references,
                credits=credits_info,
                advisory_type=item.get("type", "unreviewed"),
                source_code_location=item.get("source_code_location"),
                fetched_at=fetched_at,
                raw=item,
            )
        except Exception as e:
            logger.error("Failed to parse advisory %s: %s", item.get("ghsa_id", "unknown"), e)
            return None

    @staticmethod
    def _extract_next_url(link_header: str) -> str | None:
        """
        Extract next page URL from GitHub Link header.

        Example: <https://api.github.com/advisories?after=xxx>; rel="next"
        """
        if not link_header:
            return None

        links = link_header.split(",")
        for link in links:
            if 'rel="next"' in link:
                match = re.search(r"<([^>]+)>", link)
                if match:
                    return match.group(1)

        return None

    # --- Normalize ------------------------------------------------------
    def normalize(self, advisory: Advisory) -> dict:
        """Convert Advisory to a plain bulletin dict."""

        # Resolve published_at time
        published_at = parse_first(
            [(advisory.published_at, "api.published_at")],
            default_tz="UTC",
        )

        # Build title
        title = advisory.summary
        if advisory.package_name:
            title = f"{advisory.package_ecosystem}/{advisory.package_name}: {advisory.summary}"

        # Build summary text
        summary_parts = []
        if advisory.severity:
            summary_parts.append(f"Severity: {advisory.severity.upper()}")
        if advisory.cvss_score:
            summary_parts.append(f"CVSS: {advisory.cvss_score}")
        if advisory.cve_id:
            summary_parts.append(f"CVE: {advisory.cve_id}")
        if advisory.package_name:
            summary_parts.append(f"Package: {advisory.package_ecosystem}/{advisory.package_name}")
        if advisory.vulnerable_version_range:
            summary_parts.append(f"Affected: {advisory.vulnerable_version_range}")
        if advisory.first_patched_version:
            summary_parts.append(f"Patched: {advisory.first_patched_version}")

        summary = " | ".join(summary_parts)

        # Body text
        body_text = advisory.description or advisory.summary

        # Labels
        labels: list[str] = []
        if advisory.severity:
            labels.append(f"severity:{advisory.severity}")
        if advisory.package_ecosystem:
            labels.append(f"ecosystem:{advisory.package_ecosystem}")
        if advisory.advisory_type:
            labels.append(f"type:{advisory.advisory_type}")
        if advisory.withdrawn_at:
            labels.append("withdrawn")

        # Topics
        topics = ["official_bulletin", "github_advisory"]
        if advisory.cve_id:
            topics.append("cve")
        if advisory.package_name:
            topics.append("package_vulnerability")

        # Extra metadata
        extra: dict[str, object] = {
            "ghsa_id": advisory.ghsa_id,
        }
        if advisory.cve_id:
            extra["cve_id"] = advisory.cve_id
        if advisory.cvss_score:
            extra["cvss_score"] = advisory.cvss_score
        if advisory.cvss_vector:
            extra["cvss_vector"] = advisory.cvss_vector
        if advisory.cwe_ids:
            extra["cwe_ids"] = advisory.cwe_ids
        if advisory.cwe_names:
            extra["cwe_names"] = advisory.cwe_names
        if advisory.package_name:
            extra["package"] = {
                "name": advisory.package_name,
                "ecosystem": advisory.package_ecosystem,
                "vulnerable_range": advisory.vulnerable_version_range,
                "patched_version": advisory.first_patched_version,
            }
        if advisory.references:
            extra["references"] = advisory.references
        if advisory.credits:
            extra["credits"] = advisory.credits
        if advisory.source_code_location:
            extra["source_code_location"] = advisory.source_code_location
        if advisory.withdrawn_at:
            extra["withdrawn_at"] = advisory.withdrawn_at
        if advisory.updated_at:
            extra["updated_at"] = advisory.updated_at

        return {
            "source": {
                "source_slug": SOURCE_SLUG,
                "external_id": advisory.ghsa_id,
                "origin_url": advisory.html_url,
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
            "severity": advisory.severity if advisory.severity != "unknown" else None,
            "fetched_at": now_utc_iso(),
            "labels": labels,
            "topics": topics,
            "extra": extra,
            "raw": {"advisory": advisory.raw},
        }

    # --- Collection -----------------------------------------------------
    def collect(
        self,
        *,
        limit: int | None = None,
        force: bool = False,
        per_page: int = 30,
        max_pages: int = 1,
    ) -> tuple[list[dict], dict]:
        """
        Collect advisories from GitHub API.

        Returns:
            Tuple of (bulletins, statistics)
        """
        limit = limit or DEFAULT_LIMIT
        cached_ids = set() if force else self.load_cache()

        logger.info("Cache loaded: %d GHSA IDs", len(cached_ids))

        # Fetch advisories
        advisories = self.fetch_advisories(per_page=per_page, max_pages=max_pages)

        # Filter out cached items
        new_advisories = []
        skipped_count = 0
        for advisory in advisories:
            if advisory.ghsa_id in cached_ids:
                skipped_count += 1
                continue
            new_advisories.append(advisory)

        logger.info("New advisories: %d, Skipped (cached): %d", len(new_advisories), skipped_count)

        # Apply limit
        if limit and len(new_advisories) > limit:
            new_advisories = new_advisories[:limit]

        # Normalize to bulletins
        bulletins: list[dict] = []
        for advisory in new_advisories:
            try:
                bulletin = self.normalize(advisory)
                bulletins.append(bulletin)
            except Exception as e:
                logger.error("Failed to normalize advisory %s: %s", advisory.ghsa_id, e)

        # Update cache
        if bulletins and not force:
            new_ids = {advisory.ghsa_id for advisory in new_advisories}
            updated_cache = cached_ids | new_ids
            self.save_cache(updated_cache)
            logger.info("Cache updated: %d GHSA IDs", len(updated_cache))

        stats = {
            "items_processed": len(advisories),
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

    collector = GitHubAdvisoryCollector()
    bulletins, stats = collector.collect()

    if not bulletins:
        logger.info("No new advisories to push")
        return

    result = push_to_seclens(bulletins)
    logger.info(
        "Done: fetched=%d accepted=%s duplicates=%s skipped_cache=%d",
        stats["items_processed"],
        result.get("accepted", 0),
        result.get("duplicates", 0),
        stats["items_skipped_cache"],
    )


if __name__ == "__main__":
    main()
