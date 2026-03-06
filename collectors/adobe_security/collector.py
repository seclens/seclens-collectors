"""Adobe Product Security advisory collector.

Fetches Adobe security advisories from the Adobe PSIRT portal and pushes
them to a SecLens server. Fully standalone - no SecLens app dependencies.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 8 hours (28800s)
"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.time_helpers import parse_first, now_utc_iso

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence
from urllib.parse import urljoin
import logging

import requests
from bs4 import BeautifulSoup, Tag

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")
SOURCE_SLUG = "adobe_security"
USER_AGENT = "SeclensCollector/2.0 (adobe_security)"
BASE_URL = "https://helpx.adobe.com"
LIST_URL = os.environ.get("ADOBE_LIST_URL", f"{BASE_URL}/security/Home.html")
REQUEST_TIMEOUT = 30
REQUEST_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "User-Agent": USER_AGENT,
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean_text(value: str | None) -> str | None:
    if not value:
        return None
    normalised = value.replace("\xa0", " ").replace("\u202f", " ")
    collapsed = " ".join(normalised.split())
    return collapsed or None


def _label_slug(value: str | None) -> str | None:
    text = _clean_text(value)
    if not text:
        return None
    result: list[str] = []
    for char in text.lower():
        if char.isalnum():
            result.append(char)
        elif char in {" ", "-", "_", "/"}:
            result.append("-")
    slug = "".join(result).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or None


def _normalise_header_name(header: str | None) -> str:
    if not header:
        return ""
    return "".join(char for char in header.lower() if char.isalnum())


def _parse_date(text: str | None) -> datetime | None:
    if not text:
        return None
    cleaned = _clean_text(text)
    if not cleaned:
        return None
    formats = (
        "%m/%d/%Y",
        "%m/%d/%y",
        "%Y-%m-%d",
        "%b %d, %Y",
        "%B %d, %Y",
    )
    for fmt in formats:
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
    return None


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

@dataclass
class FetchParams:
    """Parameters controlling Adobe security bulletin fetching."""
    list_url: str = LIST_URL
    limit: int | None = None
    fetch_details: bool = True


def _fetch_listing(session: requests.Session, list_url: str, limit: int | None) -> list[dict[str, Any]]:
    response = session.get(list_url, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")

    table = soup.find("table")
    if not table:
        logger.warning("Adobe security listing table not found at %s", list_url)
        return []

    entries: list[dict[str, Any]] = []
    rows = table.find_all("tr")
    for row in rows[1:]:
        cells = row.find_all("td")
        if len(cells) < 3:
            continue

        title_cell = cells[0]
        date_posted_cell = cells[1]
        last_updated_cell = cells[2]

        anchor = title_cell.find("a", href=True)
        detail_href = anchor["href"] if anchor else None
        detail_url = urljoin(BASE_URL, detail_href) if detail_href else None

        listing_title = _clean_text(anchor.get_text(" ", strip=True)) if anchor else _clean_text(
            title_cell.get_text(" ", strip=True)
        )
        originally_posted = _clean_text(date_posted_cell.get_text(" ", strip=True))
        last_updated = _clean_text(last_updated_cell.get_text(" ", strip=True))

        external_id = None
        if listing_title:
            prefix = listing_title.split(":", 1)[0]
            external_id = _clean_text(prefix)

        origin_url = detail_url or list_url

        entry = {
            "listing_title": listing_title,
            "detail_url": detail_url,
            "origin_url": origin_url,
            "external_id": external_id,
            "originally_posted": originally_posted,
            "last_updated": last_updated,
        }
        entries.append(entry)
        if limit is not None and len(entries) >= limit:
            break
    return entries


def _fetch_detail(session: requests.Session, detail_url: str) -> dict[str, Any]:
    response = session.get(detail_url, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")

    main = soup.find("main") or soup

    intro_text = _extract_intro_text(main)
    summary_paragraphs, summary_tables = _extract_section(main, "Summary")
    affected_paragraphs, affected_tables = _extract_section_by_titles(
        main, ["Affected Product Versions", "Affected Versions"]
    )
    solution_paragraphs, solution_tables = _extract_section_by_titles(
        main, ["Solution", "Solutions"]
    )
    vulnerability_paragraphs, vulnerability_tables = _extract_section_by_titles(
        main, ["Vulnerability Details", "Vulnerabilities"]
    )
    acknowledgments_paragraphs, _ = _extract_section_by_titles(
        main, ["Acknowledgments", "Acknowledgements"]
    )

    bulletin_info: dict[str, str] | None = None
    affected_products: list[dict[str, Any]] = []
    solutions: list[dict[str, Any]] = []
    vulnerabilities: list[dict[str, Any]] = []

    candidate_tables = list(main.find_all("table"))

    for table in candidate_tables:
        headers = [_clean_text(th.get_text(" ", strip=True)) or "" for th in table.find_all("th")]
        normalised_headers = [_normalise_header_name(header) for header in headers]

        if normalised_headers == ["bulletinid", "datepublished", "priority"]:
            bulletin_info = _parse_single_row_table(headers, table)
            continue

        if normalised_headers == ["product", "version", "platform"]:
            affected_products = _parse_product_table(table)
            continue

        if normalised_headers == ["product", "version", "platform", "priority", "availability"]:
            solutions = _parse_solution_table(table)
            continue

        if any("vulnerability" in header for header in normalised_headers) and any(
            "cve" in header for header in normalised_headers
        ):
            vulnerabilities = _parse_vulnerability_table(headers, table)
            continue

    if not affected_products:
        for table in affected_tables:
            affected_products = _parse_product_table(table)
            if affected_products:
                break
    if not solutions:
        for table in solution_tables:
            solutions = _parse_solution_table(table)
            if solutions:
                break
    if not vulnerabilities:
        for table in vulnerability_tables:
            vulnerabilities = _parse_vulnerability_table(
                [_clean_text(th.get_text(" ", strip=True)) or "" for th in table.find_all("th")],
                table,
            )
            if vulnerabilities:
                break

    return {
        "intro_text": intro_text,
        "summary_paragraphs": summary_paragraphs,
        "affected_paragraphs": affected_paragraphs,
        "solution_paragraphs": solution_paragraphs,
        "bulletin_info": bulletin_info,
        "affected_products": affected_products,
        "solutions": solutions,
        "vulnerabilities": vulnerabilities,
        "vulnerability_paragraphs": vulnerability_paragraphs,
        "acknowledgments": acknowledgments_paragraphs,
    }


def _extract_intro_text(container: Tag) -> str | None:
    for paragraph in container.find_all("p"):
        text = _clean_text(paragraph.get_text(" ", strip=True))
        if text:
            return text
    return None


def _extract_section(container: Tag, heading_text: str) -> tuple[list[str], list[Tag]]:
    heading = None
    for tag in container.find_all(["h2", "h3"]):
        label = _clean_text(tag.get_text(" ", strip=True))
        if label and label.lower() == heading_text.lower():
            heading = tag
            break
    if heading is None:
        return [], []

    paragraphs: list[str] = []
    tables: list[Tag] = []

    for element in heading.next_elements:
        if element is heading:
            continue
        if isinstance(element, Tag) and element.name in {"h1", "h2", "h3"}:
            break
        if isinstance(element, Tag) and element.name == "table":
            tables.append(element)
            continue
        if isinstance(element, Tag):
            if element.find_parent("table"):
                continue
            if element.name in {"p", "li"}:
                text = _clean_text(element.get_text(" ", strip=True))
                if text:
                    paragraphs.append(text)
                continue
            if element.name in {"ul", "ol"}:
                for item in element.find_all("li"):
                    text = _clean_text(item.get_text(" ", strip=True))
                    if text:
                        paragraphs.append(text)
                continue
    unique_paragraphs = _dedupe(paragraphs)
    return unique_paragraphs, tables


def _extract_section_by_titles(
    container: Tag,
    titles: Sequence[str],
) -> tuple[list[str], list[Tag]]:
    for title in titles:
        paragraphs, tables = _extract_section(container, title)
        if paragraphs or tables:
            return paragraphs, tables
    return [], []


def _parse_single_row_table(headers: list[str], table: Tag) -> dict[str, str] | None:
    rows = table.find_all("tr")
    for row in rows[1:]:
        cells = row.find_all("td")
        if not cells:
            continue
        values = [_clean_text(cell.get_text(" ", strip=True)) or "" for cell in cells]
        if not values:
            continue
        return {
            headers[index]: values[index] if index < len(values) else ""
            for index in range(len(headers))
        }
    return None


def _parse_product_table(table: Tag) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for row in table.find_all("tr")[1:]:
        cells = row.find_all("td")
        if len(cells) != 3:
            continue
        entries.append(
            {
                "product": _clean_text(cells[0].get_text(" ", strip=True)),
                "version": _clean_text(cells[1].get_text(" ", strip=True)),
                "platform": _clean_text(cells[2].get_text(" ", strip=True)),
            }
        )
    return entries


def _parse_solution_table(table: Tag) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for row in table.find_all("tr")[1:]:
        cells = row.find_all("td")
        if len(cells) != 5:
            continue
        availability_cell = cells[4]
        availability_text = _clean_text(availability_cell.get_text(" ", strip=True))
        availability_url = None
        link = availability_cell.find("a", href=True)
        if link:
            availability_url = urljoin(BASE_URL, link["href"])
        entries.append(
            {
                "product": _clean_text(cells[0].get_text(" ", strip=True)),
                "version": _clean_text(cells[1].get_text(" ", strip=True)),
                "platform": _clean_text(cells[2].get_text(" ", strip=True)),
                "priority": _clean_text(cells[3].get_text(" ", strip=True)),
                "availability": availability_text,
                "availability_url": availability_url,
            }
        )
    return entries


def _parse_vulnerability_table(headers: list[str], table: Tag) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for row in table.find_all("tr")[1:]:
        cells = row.find_all("td")
        if not cells:
            continue
        row_data: dict[str, Any] = {}
        for index, header in enumerate(headers):
            value = _clean_text(cells[index].get_text(" ", strip=True)) if index < len(cells) else None
            row_data[header] = value
        entries.append(row_data)
    return entries


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------

def normalize(entry: dict[str, Any]) -> dict:
    """Convert an entry dict to a SecLens bulletin dict."""
    fetched_at = now_utc_iso()
    detail: dict[str, Any] | None = entry.get("detail")

    bulletin_info = detail.get("bulletin_info") if detail else None
    bulletin_id = bulletin_info.get("Bulletin ID") if isinstance(bulletin_info, dict) else entry.get("external_id")
    bulletin_priority = bulletin_info.get("Priority") if isinstance(bulletin_info, dict) else None
    date_published = bulletin_info.get("Date Published") if isinstance(bulletin_info, dict) else None

    intro_text = detail.get("intro_text") if detail else None
    summary_paragraphs = detail.get("summary_paragraphs") if detail else []
    affected_paragraphs = detail.get("affected_paragraphs") if detail else []
    solution_paragraphs = detail.get("solution_paragraphs") if detail else []
    affected_products = detail.get("affected_products") if detail else []
    solutions = detail.get("solutions") if detail else []
    vulnerabilities = detail.get("vulnerabilities") if detail else []
    vulnerability_paragraphs = detail.get("vulnerability_paragraphs") if detail else []
    acknowledgments = detail.get("acknowledgments") if detail else []

    title = intro_text or entry.get("listing_title") or entry.get("origin_url")
    summary = summary_paragraphs[0] if summary_paragraphs else intro_text

    body_lines: list[str] = []
    for line in summary_paragraphs:
        if line not in body_lines:
            body_lines.append(line)
    for line in solution_paragraphs:
        if line not in body_lines:
            body_lines.append(line)
    for line in affected_paragraphs:
        if line not in body_lines:
            body_lines.append(line)
    if affected_products:
        body_lines.append("Affected products:")
        for product in affected_products:
            parts = [
                product.get("product"),
                product.get("version"),
                product.get("platform"),
            ]
            body_lines.append(" - " + " | ".join(part for part in parts if part))
    if solutions:
        body_lines.append("Solutions:")
        for solution in solutions:
            parts = [
                solution.get("product"),
                solution.get("version"),
                solution.get("platform"),
            ]
            suffix = []
            if solution.get("priority"):
                suffix.append(f"Priority {solution['priority']}")
            if solution.get("availability"):
                suffix.append(solution["availability"])
            line = " - " + " | ".join(part for part in parts if part)
            if suffix:
                line += f" ({'; '.join(suffix)})"
            body_lines.append(line)
    for line in vulnerability_paragraphs:
        if line not in body_lines:
            body_lines.append(line)
    if vulnerabilities:
        body_lines.append("Vulnerabilities:")
        for vuln in vulnerabilities:
            components = [
                vuln.get("Vulnerability Category"),
                vuln.get("Vulnerability Impact"),
                vuln.get("Severity"),
                vuln.get("CVE Number"),
            ]
            details = [comp for comp in components if comp]
            if vuln.get("CVSS base score"):
                details.append(f"CVSS {vuln['CVSS base score']}")
            if vuln.get("CVSS vector"):
                details.append(vuln["CVSS vector"])
            body_lines.append(" - " + " | ".join(details))
    for line in acknowledgments:
        body_lines.append(f"Acknowledgment: {line}")

    body_text = "\n".join(body_lines) or None

    candidates: list[tuple[object, str]] = []
    parsed_date = _parse_date(date_published) if date_published else None
    if parsed_date:
        candidates.append((parsed_date, "detail.date_published_parsed"))
    if date_published:
        candidates.append((date_published, "detail.date_published"))
    originally_posted = entry.get("originally_posted")
    if originally_posted:
        candidates.append((originally_posted, "listing.originally_posted"))
    last_updated = entry.get("last_updated")
    if last_updated:
        candidates.append((last_updated, "listing.last_updated"))

    published_at = parse_first(candidates, default_tz="UTC")

    labels: list[str] = ["vendor:adobe"]
    for product in affected_products or []:
        slug = _label_slug(product.get("product"))
        if slug:
            labels.append(f"product:{slug}")
    if bulletin_priority:
        labels.append(f"priority:{bulletin_priority}")
    if vulnerabilities:
        labels.append("contains:cve")
    if last_updated and last_updated != originally_posted:
        labels.append("has:last-updated")
    labels = _dedupe(labels)

    topics = ["vendor-update", "official_advisory"]

    extra: dict[str, Any] = {
        "bulletin_id": bulletin_id,
        "priority": bulletin_priority,
        "originally_posted": originally_posted,
        "last_updated": last_updated,
        "summary_paragraphs": summary_paragraphs,
        "affected_paragraphs": affected_paragraphs,
        "solution_paragraphs": solution_paragraphs,
        "affected_products": affected_products,
        "solutions": solutions,
        "vulnerabilities": vulnerabilities,
        "vulnerability_paragraphs": vulnerability_paragraphs,
        "acknowledgments": acknowledgments,
        "detail_url": entry.get("detail_url"),
    }

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": bulletin_id,
            "origin_url": entry.get("detail_url") or entry.get("origin_url"),
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
        "extra": {key: value for key, value in extra.items() if value},
        "raw": entry,
    }


# ---------------------------------------------------------------------------
# Collect
# ---------------------------------------------------------------------------

def collect(
    *,
    list_url: str | None = None,
    limit: int | None = None,
    fetch_details: bool = True,
) -> tuple[list[dict], dict]:
    """Collect and normalize Adobe security advisories."""
    session = requests.Session()
    session.headers.update(REQUEST_HEADERS)

    url = list_url or LIST_URL
    listing = _fetch_listing(session, url, limit)
    logger.info("Fetched %d entries from listing", len(listing))

    if fetch_details:
        enriched: list[dict[str, Any]] = []
        for entry in listing:
            detail_url = entry.get("detail_url")
            detail_data: dict[str, Any] | None = None
            if detail_url:
                try:
                    detail_data = _fetch_detail(session, detail_url)
                except Exception as exc:
                    logger.exception("Failed to fetch Adobe detail %s", detail_url, exc_info=exc)
            enriched.append({**entry, "detail": detail_data})
        items = enriched
    else:
        items = listing

    bulletins: list[dict] = []
    for item in items:
        try:
            bulletins.append(normalize(item))
        except Exception as exc:
            logger.exception("Failed to normalise Adobe security entry: %s", item, exc_info=exc)

    stats = {
        "items_processed": len(listing),
        "items_created": len(bulletins),
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
        print(f"Done: {stats['items_processed']} processed, 0 new items")
        return

    result = push_to_seclens(bulletins)
    print(
        f"Done: {stats['items_processed']} processed, "
        f"{len(bulletins)} fetched, "
        f"{result.get('accepted', 0)} accepted, "
        f"{result.get('duplicates', 0)} duplicates"
    )


if __name__ == "__main__":
    main()
