"""CCGP local government procurement collector - standalone version.

Scrapes local government procurement announcements from CCGP (China Government
Procurement Network), filters by security-related keywords, and pushes to
a SecLens server.

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
import time
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

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

DEFAULT_LOCAL_LIST_URL = "https://www.ccgp.gov.cn/cggg/dfgg/"
DEFAULT_CENTRAL_LIST_URL = "https://www.ccgp.gov.cn/cggg/zygg/"
SOURCE_SLUG = "ccgp_local_procurement"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)
REQUEST_HEADERS = {
    "User-Agent": USER_AGENT,
    "Referer": "https://www.ccgp.gov.cn/",
    "Accept-Language": "zh-CN,zh;q=0.9",
}
REQUEST_TIMEOUT = 30
DEFAULT_TOPIC = "security_procurement"
STATE_FILE_NAME = ".cursor"
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)
KEYWORDS = (
    "网安",
    "网络安全",
    "信息安全",
    "提示感知",
    "态势感知",
    "等级保护",
    "防火墙",
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


def _state_file_path() -> Path:
    return Path(__file__).resolve().parent / STATE_FILE_NAME


def load_cursor() -> str | None:
    path = _state_file_path()
    if not path.exists():
        return None
    value = path.read_text(encoding="utf-8").strip()
    return value or None


def save_cursor(cursor: str) -> None:
    _state_file_path().write_text(cursor.strip(), encoding="utf-8")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _norm_rel(value: str | list[str] | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _ensure_response_encoding(response: requests.Response) -> None:
    """Force UTF-8 decoding when the server omits charset headers."""
    encoding = getattr(response, "encoding", None)
    if encoding and encoding.lower() != "iso-8859-1":
        return
    apparent = getattr(response, "apparent_encoding", None)
    if apparent:
        response.encoding = apparent
    else:
        response.encoding = "utf-8"


def _contains_keyword(text: str | None) -> bool:
    if not text:
        return False
    return any(keyword in text for keyword in KEYWORDS)


def _request_with_retry(
    session: requests.Session,
    url: str,
    *,
    method: str = "GET",
    max_attempts: int = 3,
    attempt_delay: float = 1.0,
    timeout: int = 30,
    **kwargs,
) -> requests.Response:
    """Issue an HTTP request with basic retry/backoff for transient failures."""
    attempt = 1
    last_exc: requests.RequestException | None = None
    method = method.upper()

    while attempt <= max_attempts:
        try:
            response = session.request(method, url, timeout=timeout, **kwargs)
            if response.status_code < 400:
                return response

            http_error = requests.HTTPError(
                f"{response.status_code} {response.reason}", response=response
            )
            should_retry = response.status_code in {429, 500, 502, 503, 504}
            if not should_retry or attempt == max_attempts:
                raise http_error
            last_exc = http_error
        except requests.RequestException as exc:
            last_exc = exc
            if attempt == max_attempts:
                break
        sleep_for = attempt_delay * (2 ** (attempt - 1))
        logger.warning(
            "[RETRY] %s attempt %s/%s failed for %s: %s. Retrying in %.1fs",
            method, attempt, max_attempts, url, last_exc, sleep_for,
        )
        time.sleep(sleep_for)
        attempt += 1

    assert last_exc is not None
    raise last_exc


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


def fetch_list(
    list_url: str = DEFAULT_LOCAL_LIST_URL,
    limit: int | None = None,
) -> list[dict]:
    """Fetch procurement announcement list from CCGP."""
    session = requests.Session()
    session.headers.update(REQUEST_HEADERS)

    logger.info("Fetching list: %s", list_url)
    response = _request_with_retry(session, list_url, method="GET", timeout=REQUEST_TIMEOUT)
    _ensure_response_encoding(response)
    soup = BeautifulSoup(response.text, "html.parser")

    items: list[dict] = []
    for li in soup.select("ul.c_list_bid li"):
        anchor = li.find("a")
        if not anchor or not anchor.get("href"):
            continue
        title = anchor.get("title") or anchor.get_text(strip=True)
        link = urljoin(list_url, anchor["href"])

        ems = li.find_all("em")
        bulletin_type = None
        published_raw = None
        region = None
        purchaser = None
        order_index = 0
        for em in ems:
            rel = _norm_rel(em.get("rel"))
            text_value = em.get_text(strip=True)
            if rel == "bxlx":
                bulletin_type = text_value
                continue
            if order_index == 0:
                published_raw = text_value
            elif order_index == 1:
                region = text_value
            elif order_index == 2:
                purchaser = text_value
            order_index += 1

        summary = anchor.get_text(strip=True)
        items.append(
            {
                "title": title,
                "summary": summary,
                "detail_url": link,
                "published_raw": published_raw,
                "bulletin_type": bulletin_type,
                "region": region,
                "purchaser": purchaser,
            }
        )
        if limit and len(items) >= limit:
            break

    logger.info("Fetched %d items from list", len(items))
    return items


def fetch_detail(url: str) -> BeautifulSoup | None:
    """Fetch detail page content."""
    session = requests.Session()
    session.headers.update(REQUEST_HEADERS)
    response = _request_with_retry(session, url, method="GET", timeout=REQUEST_TIMEOUT)
    _ensure_response_encoding(response)
    return BeautifulSoup(response.text, "html.parser")


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------


def normalize(
    item: dict,
    source_slug: str = SOURCE_SLUG,
    topics: list[str] | None = None,
    manifest: dict | None = MANIFEST,
    manifest_hash: str | None = MANIFEST_HASH,
    manifest_version: str | None = MANIFEST_VERSION,
) -> dict | None:
    """Normalize a CCGP procurement item to a SecLens bulletin dict."""
    topics = topics or [DEFAULT_TOPIC]

    try:
        detail_soup = fetch_detail(item["detail_url"])
    except requests.RequestException:
        logger.warning("Failed to fetch detail: %s", item["detail_url"])
        return None

    if detail_soup is None:
        return None

    content_node = detail_soup.select_one("div.vF_detail_content")
    if content_node is None:
        return None

    body_text = content_node.get_text("\n", strip=True)
    text_for_filter = f"{item['title']}\n{body_text}"
    if not _contains_keyword(text_for_filter):
        return None

    published_at = parse_first(
        [(item.get("published_raw"), "list.published_at")],
        default_tz="Asia/Shanghai",
    )

    summary = body_text[:280] if body_text else item.get("summary")

    labels: list[str] = []
    if item.get("bulletin_type"):
        labels.append(f"type:{item['bulletin_type']}")
    if item.get("region"):
        labels.append(f"region:{item['region']}")
    if item.get("purchaser"):
        labels.append(f"buyer:{item['purchaser']}")

    extra: dict = {
        "bulletin_type": item.get("bulletin_type"),
        "region": item.get("region"),
        "purchaser": item.get("purchaser"),
    }

    return {
        "source": {
            "source_slug": source_slug,
            "external_id": item["detail_url"],
            "origin_url": item["detail_url"],
            "manifest": manifest,
            "manifest_hash": manifest_hash,
            "manifest_version": manifest_version,
        },
        "content": {
            "title": item["title"],
            "summary": summary,
            "body_text": body_text,
            "published_at": published_at,
            "language": "zh",
        },
        "severity": None,
        "fetched_at": now_utc_iso(),
        "labels": labels,
        "topics": topics,
        "extra": extra,
        "raw": dict(item),
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

    list_url = os.environ.get("CCGP_LIST_URL", DEFAULT_LOCAL_LIST_URL)
    items = fetch_list(list_url=list_url)
    latest_cursor = items[0]["detail_url"] if items else None
    previous_cursor = load_cursor()
    if previous_cursor:
        filtered_items: list[dict] = []
        for item in items:
            cursor_value = str(item.get("detail_url") or "")
            if cursor_value == previous_cursor:
                break
            filtered_items.append(item)
        items = filtered_items
        logger.info(
            "Cursor check: previous=%s, pending=%d",
            previous_cursor,
            len(items),
        )

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
    if latest_cursor:
        save_cursor(latest_cursor)
    logger.info(
        "Done: fetched=%d accepted=%s duplicates=%s",
        len(bulletins),
        result.get("accepted", 0),
        result.get("duplicates", 0),
    )


if __name__ == "__main__":
    main()
