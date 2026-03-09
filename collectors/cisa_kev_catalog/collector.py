from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import requests

try:
    from shared.manifest import load_manifest_for_slug
    from shared.time_helpers import now_utc_iso, parse_datetime
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from shared.manifest import load_manifest_for_slug
    from shared.time_helpers import now_utc_iso, parse_datetime

SOURCE_SLUG = "cisa_kev_catalog"
SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")
JSON_FEED_URL = os.environ.get(
    "CISA_KEV_JSON_FEED_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
REQUEST_TIMEOUT = 45
USER_AGENT = "SeclensCollector/2.0 (cisa_kev_catalog)"
BATCH_SIZE = int(os.environ.get("CISA_KEV_BATCH_SIZE", "200"))
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(
    SOURCE_SLUG, repo_root=Path(__file__).resolve().parents[2]
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(SOURCE_SLUG)


def _trim(value: str | None) -> str | None:
    if not value:
        return None
    value = " ".join(value.split()).strip()
    return value or None


def fetch_items() -> list[dict]:
    resp = requests.get(
        JSON_FEED_URL,
        timeout=REQUEST_TIMEOUT,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
        },
    )
    resp.raise_for_status()
    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    if not isinstance(vulns, list):
        return []
    return vulns


def normalize(item: dict) -> dict:
    cve = _trim(item.get("cveID")) or _trim(item.get("cveId")) or ""
    vendor = _trim(item.get("vendorProject"))
    product = _trim(item.get("product"))
    vuln_name = _trim(item.get("vulnerabilityName"))
    notes = _trim(item.get("notes"))

    title = vuln_name or cve or "CISA KEV Vulnerability"
    summary_parts = [x for x in [vendor, product, notes] if x]
    summary = " | ".join(summary_parts) if summary_parts else None

    published_at = parse_datetime(item.get("dateAdded"), default_tz="UTC")
    due_date = parse_datetime(item.get("dueDate"), default_tz="UTC")

    ext = cve or f"kev-{vendor}-{product}-{item.get('dateAdded')}"
    origin_url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

    labels = ["source:cisa", "catalog:kev", "type:vulnerability"]
    if _trim(item.get("knownRansomwareCampaignUse")):
        labels.append(f"ransomware:{_trim(item.get('knownRansomwareCampaignUse')).lower()}")

    body_lines = []
    if notes:
        body_lines.append(f"Notes: {notes}")
    if item.get("requiredAction"):
        body_lines.append(f"Required action: {item.get('requiredAction')}")
    if item.get("knownRansomwareCampaignUse"):
        body_lines.append(f"Known ransomware campaign use: {item.get('knownRansomwareCampaignUse')}")
    if item.get("dueDate"):
        body_lines.append(f"Due date: {item.get('dueDate')}")
    body_text = "\n".join(body_lines) if body_lines else None

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": ext,
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
        "fetched_at": now_utc_iso(),
        "labels": labels,
        "topics": ["vulnerability", "known-exploited"],
        "extra": {
            "cve_id": cve,
            "vendor_project": vendor,
            "product": product,
            "required_action": _trim(item.get("requiredAction")),
            "known_ransomware_campaign_use": _trim(item.get("knownRansomwareCampaignUse")),
            "due_date": due_date,
            "raw_date_added": item.get("dateAdded"),
        },
    }


def push(bulletins: list[dict]) -> dict:
    endpoint = f"{SECLENS_URL}/v1/ingest/bulletins"
    headers = {
        "Authorization": f"Bearer {SECLENS_TOKEN}",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    accepted = 0
    duplicates = 0

    for i in range(0, len(bulletins), BATCH_SIZE):
        chunk = bulletins[i : i + BATCH_SIZE]
        resp = requests.post(endpoint, json=chunk, timeout=REQUEST_TIMEOUT, headers=headers)
        if resp.status_code >= 400:
            logger.error("Push failed for batch %s-%s: %s %s", i, i + len(chunk), resp.status_code, resp.text[:400])
            resp.raise_for_status()
        payload = resp.json()
        accepted += int(payload.get("accepted", 0) or 0)
        duplicates += int(payload.get("duplicates", 0) or 0)

    return {"accepted": accepted, "duplicates": duplicates}


def main() -> None:
    if not SECLENS_URL or not SECLENS_TOKEN:
        raise SystemExit("SECLENS_URL and SECLENS_TOKEN are required")

    items = fetch_items()
    logger.info("Fetched %d KEV entries", len(items))
    bulletins = [normalize(i) for i in items if isinstance(i, dict)]
    if not bulletins:
        logger.info("No bulletins to push")
        return

    result = push(bulletins)
    logger.info("Push done: accepted=%s duplicates=%s", result.get("accepted"), result.get("duplicates"))


if __name__ == "__main__":
    main()
