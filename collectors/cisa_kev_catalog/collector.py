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
FALLBACK_JSON_FEED_URL = os.environ.get("CISA_KEV_JSON_FEED_FALLBACK_URL", "").strip()
CATALOG_URL = os.environ.get(
    "CISA_KEV_CATALOG_URL",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
)
REQUEST_TIMEOUT = 40
USER_AGENT = "SeclensCollector/2.0 (cisa_kev_catalog)"
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(
    SOURCE_SLUG, repo_root=Path(__file__).resolve().parents[2]
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(SOURCE_SLUG)


def _trim(v: str | None) -> str | None:
    if not v:
        return None
    v = " ".join(v.split()).strip()
    return v or None


def _fetch_json(url: str) -> dict:
    resp = requests.get(
        url,
        timeout=REQUEST_TIMEOUT,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Referer": CATALOG_URL,
        },
    )
    resp.raise_for_status()
    return resp.json()


def fetch_vulnerabilities() -> tuple[list[dict], dict]:
    errors: list[str] = []
    urls = [JSON_FEED_URL]
    if FALLBACK_JSON_FEED_URL:
        urls.append(FALLBACK_JSON_FEED_URL)

    for url in urls:
        try:
            data = _fetch_json(url)
            vulns = data.get("vulnerabilities", []) or []
            data.setdefault("_feed_url", url)
            return vulns, data
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{url}: {exc}")

    raise RuntimeError("Failed to fetch CISA KEV JSON feed. " + " | ".join(errors))


def normalize(item: dict, catalog_meta: dict) -> dict:
    cve_id = _trim(item.get("cveID")) or _trim(item.get("cveId")) or "unknown"
    vendor = _trim(item.get("vendorProject"))
    product = _trim(item.get("product"))
    title = f"{cve_id} - {vendor or ''} {product or ''}".strip(" -")

    short_desc = _trim(item.get("shortDescription"))
    required_action = _trim(item.get("requiredAction"))
    due_date = _trim(item.get("dueDate"))
    date_added = parse_datetime(item.get("dateAdded"))

    summary_parts = [x for x in [short_desc, f"Required Action: {required_action}" if required_action else None, f"Due Date: {due_date}" if due_date else None] if x]
    summary = " | ".join(summary_parts) if summary_parts else None

    labels = ["source:cisa", "type:kev"]
    if _trim(item.get("knownRansomwareCampaignUse")):
        labels.append(f"ransomware:{item.get('knownRansomwareCampaignUse')}")

    return {
        "source": {
            "source_slug": SOURCE_SLUG,
            "external_id": cve_id,
            "origin_url": CATALOG_URL,
            "manifest": MANIFEST,
            "manifest_hash": MANIFEST_HASH,
            "manifest_version": MANIFEST_VERSION,
        },
        "content": {
            "title": title,
            "summary": summary,
            "published_at": date_added,
            "language": "en",
        },
        "fetched_at": now_utc_iso(),
        "labels": labels,
        "topics": ["vulnerability", "kev", "exploited-in-the-wild"],
        "extra": {
            "vendorProject": vendor,
            "product": product,
            "vulnerabilityName": _trim(item.get("vulnerabilityName")),
            "dateAdded": _trim(item.get("dateAdded")),
            "dueDate": due_date,
            "requiredAction": required_action,
            "knownRansomwareCampaignUse": _trim(item.get("knownRansomwareCampaignUse")),
            "notes": _trim(item.get("notes")),
            "json_feed_url": catalog_meta.get("_feed_url") or JSON_FEED_URL,
            "catalog_count": catalog_meta.get("count") or len(catalog_meta.get("vulnerabilities", []) or []),
        },
    }


def push(bulletins: list[dict]) -> dict:
    endpoint = f"{SECLENS_URL}/v1/ingest/bulletins"
    resp = requests.post(
        endpoint,
        json=bulletins,
        timeout=REQUEST_TIMEOUT,
        headers={
            "Authorization": f"Bearer {SECLENS_TOKEN}",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    resp.raise_for_status()
    return resp.json()


def main() -> None:
    if not SECLENS_URL or not SECLENS_TOKEN:
        raise SystemExit("SECLENS_URL and SECLENS_TOKEN are required")

    vulns, meta = fetch_vulnerabilities()
    logger.info("Fetched %d vulnerabilities from CISA KEV JSON", len(vulns))
    bulletins = [normalize(v, meta) for v in vulns if v.get("cveID") or v.get("cveId")]

    if not bulletins:
        logger.info("No bulletins to push")
        return

    result = push(bulletins)
    logger.info("Push done: accepted=%s duplicates=%s", result.get("accepted"), result.get("duplicates"))


if __name__ == "__main__":
    main()
