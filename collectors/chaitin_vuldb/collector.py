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

SOURCE_SLUG = "chaitin_vuldb"
SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")
API_URL = os.environ.get(
    "CHAITIN_VULDB_API_URL",
    "https://stack.chaitin.com/api/v2/vuln/list/?limit=30&offset=0&search=",
)
REQUEST_TIMEOUT = 30
USER_AGENT = "SeclensCollector/2.0 (chaitin_vuldb)"
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
        API_URL,
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    resp.raise_for_status()
    data = resp.json().get("data", {})
    return data.get("list", []) or []


def normalize(item: dict) -> dict:
    vuln_id = str(item.get("id") or "").strip()
    origin_url = f"https://stack.chaitin.com/vuldb/detail/{vuln_id}" if vuln_id else "https://stack.chaitin.com/vuldb"

    cve = _trim(item.get("cve_id"))
    cnvd = _trim(item.get("cnvd_id"))
    cnnvd = _trim(item.get("cnnvd_id"))
    severity = _trim(item.get("severity"))

    ext = cve or vuln_id or origin_url
    title = _trim(item.get("title")) or "(untitled)"
    summary = _trim(item.get("summary"))
    body_parts: list[str] = []
    impact = _trim(item.get("impact"))
    if impact:
        body_parts.append(f"Impact: {impact}")
    fix_steps = _trim(item.get("fix_steps"))
    if fix_steps:
        body_parts.append(f"Mitigation: {fix_steps}")
    refs = item.get("references") or []
    if isinstance(refs, list) and refs:
        ref_lines = [str(r).strip() for r in refs if str(r).strip()]
        if ref_lines:
            body_parts.append("References:\n" + "\n".join(ref_lines))
    body_text = "\n\n".join(body_parts) if body_parts else None

    published_at = parse_datetime(item.get("disclosure_date")) or parse_datetime(item.get("created_at"))

    labels: list[str] = ["source:chaitin", "type:vuln"]
    if severity:
        labels.append(f"severity:{severity.lower()}")

    topics = [x for x in ["vulnerability", "security-advisory", "china"] if x]

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
            "language": "zh",
        },
        "fetched_at": now_utc_iso(),
        "labels": labels,
        "topics": topics,
        "extra": {
            "vuln_id": vuln_id,
            "cve_id": cve,
            "cnvd_id": cnvd,
            "cnnvd_id": cnnvd,
            "severity": severity,
            "cvss3": item.get("cvss3"),
            "references": item.get("references") or [],
            "raw_updated_at": item.get("updated_at"),
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

    items = fetch_items()
    logger.info("Fetched %d items from Chaitin API", len(items))
    bulletins = [normalize(i) for i in items if i.get("id")]
    if not bulletins:
        logger.info("No bulletins to push")
        return

    result = push(bulletins)
    logger.info("Push done: accepted=%s duplicates=%s", result.get("accepted"), result.get("duplicates"))


if __name__ == "__main__":
    main()
