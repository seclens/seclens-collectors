"""ThreatBook SilverFox IOC Collector (standalone).

Fetches hot IOC intelligence for the SilverFox malware family from ThreatBook,
including IPs, domains, SHA256 hashes (with optional MD5/SHA1 enrichment),
and dropped file paths.

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
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.time_helpers import parse_first, now_utc_iso

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECLENS_URL = os.environ.get("SECLENS_URL", "").rstrip("/")
SECLENS_TOKEN = os.environ.get("SECLENS_TOKEN", "")

SOURCE_SLUG = "threatbook_silverfox_ioc"
HOT_IOC_API_URL = "https://s.threatbook.com/apis/cybercrime-trend/get-hot-ioc"
FILE_REPORT_API_URL = "https://api.threatbook.cn/v3/file/report"
DETAIL_PAGE_URL = "https://s.threatbook.com/cybercrime/silverfox"
SANDBOX_TYPE = "win10_1903_enx64_office2016"
USER_AGENT = "SeclensCollector/2.0 (threatbook_silverfox_ioc)"
REQUEST_TIMEOUT = 30

CACHE_FILE = ".cache.json"
IOC_CACHE_LIMIT = 500
HASH_CACHE_LIMIT = 300

DEFAULT_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "Content-Type": "application/json",
    "Referer": "https://s.threatbook.com/cybercrime/silverfox",
    "User-Agent": "Mozilla/5.0 (compatible; silverfox-ioc-monitor/1.0)",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class IocItem:
    """Single IOC item."""
    type: str  # ip, domain, sha256, file_path
    value: str
    sha256: Optional[str] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    file_name: Optional[str] = None
    file_path: Optional[str] = None
    batch_id: Optional[str] = None
    is_new: bool = False


@dataclass
class IOCBatch:
    """A batch of IOC data."""
    batch_id: str
    update_time: datetime
    update_time_ms: int
    items: List[IocItem] = field(default_factory=list)
    new_items: List[IocItem] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def ips(self) -> List[IocItem]:
        return [i for i in self.items if i.type == "ip"]

    @property
    def domains(self) -> List[IocItem]:
        return [i for i in self.items if i.type == "domain"]

    @property
    def hashes(self) -> List[IocItem]:
        return [i for i in self.items if i.type == "sha256"]

    @property
    def file_paths(self) -> List[IocItem]:
        return [i for i in self.items if i.type == "file_path"]

    @property
    def new_ips(self) -> List[IocItem]:
        return [i for i in self.new_items if i.type == "ip"]

    @property
    def new_domains(self) -> List[IocItem]:
        return [i for i in self.new_items if i.type == "domain"]

    @property
    def new_hashes(self) -> List[IocItem]:
        return [i for i in self.new_items if i.type == "sha256"]

    @property
    def new_file_paths(self) -> List[IocItem]:
        return [i for i in self.new_items if i.type == "file_path"]


# ---------------------------------------------------------------------------
# Cache Management
# ---------------------------------------------------------------------------

def load_cache(cache_path: Path) -> Dict[str, Any]:
    """Load cache from file."""
    try:
        with open(cache_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if "known_iocs" not in data:
                data["known_iocs"] = {"ip": [], "domain": [], "sha256": [], "file_path": []}
            if "hash_lookups" not in data:
                data["hash_lookups"] = {}
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            "known_iocs": {"ip": [], "domain": [], "sha256": [], "file_path": []},
            "hash_lookups": {},
            "last_batch_id": None,
        }


def save_cache(cache_path: Path, cache_data: Dict[str, Any]) -> None:
    """Save cache to file, limiting cache size."""
    known_iocs = cache_data.get("known_iocs", {})
    for ioc_type in ["ip", "domain", "sha256", "file_path"]:
        if ioc_type in known_iocs and len(known_iocs[ioc_type]) > IOC_CACHE_LIMIT:
            known_iocs[ioc_type] = known_iocs[ioc_type][-IOC_CACHE_LIMIT:]

    hash_lookups = cache_data.get("hash_lookups", {})
    if len(hash_lookups) > HASH_CACHE_LIMIT:
        sorted_items = sorted(
            hash_lookups.items(),
            key=lambda x: x[1].get("cached_at", ""),
            reverse=True
        )
        cache_data["hash_lookups"] = dict(sorted_items[:HASH_CACHE_LIMIT])

    with open(cache_path, 'w', encoding='utf-8') as f:
        json.dump(cache_data, f, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Markdown Content Generator
# ---------------------------------------------------------------------------

def generate_markdown_content(batch: IOCBatch) -> str:
    """Generate Markdown report content (new IOCs only)."""
    update_time_str = batch.update_time.strftime("%Y-%m-%d %H:%M:%S UTC")
    fetch_time_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        "# 银狐恶意软件 IOC 情报(新增)",
        "",
        "## 基本信息",
        "",
        f"- **批次ID**: {batch.batch_id}",
        f"- **数据更新时间**: {update_time_str}",
        f"- **采集时间**: {fetch_time_str}",
        "",
        "## 本批次新增统计",
        "",
        "| 类型 | 新增数量 |",
        "|------|----------|",
        f"| 恶意IP | {len(batch.new_ips)} |",
        f"| 恶意域名 | {len(batch.new_domains)} |",
        f"| 恶意样本 | {len(batch.new_hashes)} |",
        f"| 释放路径 | {len(batch.new_file_paths)} |",
        "",
    ]

    if batch.new_ips:
        lines.extend([
            "## 新增恶意 IP 地址",
            "",
            "| # | IP 地址 |",
            "|---|---------|",
        ])
        for idx, item in enumerate(batch.new_ips, 1):
            lines.append(f"| {idx} | `{item.value}` |")
        lines.append("")

    if batch.new_domains:
        lines.extend([
            "## 新增恶意域名",
            "",
            "| # | 域名 |",
            "|---|------|",
        ])
        for idx, item in enumerate(batch.new_domains, 1):
            lines.append(f"| {idx} | `{item.value}` |")
        lines.append("")

    if batch.new_hashes:
        lines.extend([
            "## 新增恶意样本哈希",
            "",
            "| # | SHA256 | MD5 | SHA1 |",
            "|---|--------|-----|------|",
        ])
        for idx, item in enumerate(batch.new_hashes, 1):
            md5 = f"`{item.md5}`" if item.md5 else "-"
            sha1 = f"`{item.sha1}`" if item.sha1 else "-"
            sha256_display = f"`{item.sha256[:16]}...{item.sha256[-8:]}`" if item.sha256 else "-"
            lines.append(f"| {idx} | {sha256_display} | {md5} | {sha1} |")
        lines.append("")

    if batch.new_file_paths:
        lines.extend([
            "## 新增释放文件路径",
            "",
            "| # | 文件路径 | 文件名 |",
            "|---|----------|--------|",
        ])
        for idx, item in enumerate(batch.new_file_paths, 1):
            file_name = f"`{item.file_name}`" if item.file_name else "-"
            file_path = f"`{item.file_path}`" if item.file_path else "-"
            lines.append(f"| {idx} | {file_path} | {file_name} |")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class ThreatBookSilverFoxIOCCollector:
    """Fetch and normalize ThreatBook SilverFox IOC data."""

    def __init__(
        self,
        session: requests.Session | None = None,
        threatbook_api_key: str | None = None,
        skip_hash_lookup: bool = False,
    ) -> None:
        self.session = session or requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

        self.cache_path = Path(__file__).parent / CACHE_FILE
        self.cache = load_cache(self.cache_path)

        self.threatbook_api_key = threatbook_api_key or os.environ.get("THREATBOOK_CN_API_KEY")
        self.skip_hash_lookup = skip_hash_lookup

        if not self.threatbook_api_key and not skip_hash_lookup:
            logger.warning(
                "[SilverFox IOC] THREATBOOK_CN_API_KEY not set, hash lookup will be skipped"
            )
            self.skip_hash_lookup = True

    def _get_known_iocs(self, ioc_type: str) -> Set[str]:
        return set(self.cache.get("known_iocs", {}).get(ioc_type, []))

    def _add_known_ioc(self, ioc_type: str, value: str) -> None:
        if "known_iocs" not in self.cache:
            self.cache["known_iocs"] = {}
        if ioc_type not in self.cache["known_iocs"]:
            self.cache["known_iocs"][ioc_type] = []
        if value not in self.cache["known_iocs"][ioc_type]:
            self.cache["known_iocs"][ioc_type].append(value)

    def fetch_hot_ioc(self) -> Dict[str, Any] | None:
        """Fetch hot IOC data from ThreatBook API."""
        try:
            response = self.session.get(HOT_IOC_API_URL, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            body = response.json()

            if body.get("response_code") != 0:
                logger.error("[SilverFox IOC] API error: %s", body.get("verbose_msg"))
                return None

            return body.get("data", {})

        except Exception as e:
            logger.error("[SilverFox IOC] Failed to fetch IOC data: %s", e)
            return None

    def lookup_hash(self, sha256: str) -> Dict[str, Optional[str]]:
        """Look up MD5 and SHA1 for a given SHA256 hash."""
        cached = self.cache.get("hash_lookups", {}).get(sha256)
        if cached and cached.get("md5"):
            logger.debug("[SilverFox IOC] Hash cache hit: %s...", sha256[:16])
            return {"sha256": sha256, "md5": cached.get("md5"), "sha1": cached.get("sha1")}

        if self.skip_hash_lookup:
            return {"sha256": sha256, "md5": None, "sha1": None}

        try:
            params = {
                "apikey": self.threatbook_api_key,
                "sandbox_type": SANDBOX_TYPE,
                "resource": sha256,
            }

            response = self.session.get(FILE_REPORT_API_URL, params=params, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            body = response.json()

            summary = body.get("data", {}).get("summary", {})
            md5 = summary.get("md5")
            sha1 = summary.get("sha1")

            if "hash_lookups" not in self.cache:
                self.cache["hash_lookups"] = {}
            self.cache["hash_lookups"][sha256] = {
                "md5": md5,
                "sha1": sha1,
                "cached_at": now_utc_iso(),
            }

            if md5:
                logger.info("[SilverFox IOC] Hash converted: %s... -> MD5: %s", sha256[:16], md5)
            else:
                logger.warning("[SilverFox IOC] Hash lookup no result: %s...", sha256[:16])

            return {"sha256": sha256, "md5": md5, "sha1": sha1}

        except Exception as e:
            logger.warning("[SilverFox IOC] Hash lookup error: %s... - %s", sha256[:16], e)
            return {"sha256": sha256, "md5": None, "sha1": None}

    def enrich_new_hashes(self, new_sha256_list: List[str], delay: float = 1.0) -> Dict[str, Dict[str, Optional[str]]]:
        """Only enrich new SHA256 hashes with MD5/SHA1 conversion."""
        results = {}
        for i, sha256 in enumerate(new_sha256_list):
            if i > 0:
                time.sleep(delay)
            results[sha256] = self.lookup_hash(sha256)
        return results

    def build_items(self, raw: Dict[str, Any], hash_details: Dict[str, Dict[str, Optional[str]]], batch_id: str) -> Tuple[List[IocItem], List[IocItem]]:
        """Build IOC item lists, distinguishing new vs existing items."""
        all_items: List[IocItem] = []
        new_items: List[IocItem] = []

        known_ips = self._get_known_iocs("ip")
        known_domains = self._get_known_iocs("domain")
        known_hashes = self._get_known_iocs("sha256")
        known_paths = self._get_known_iocs("file_path")

        for ip in raw.get("ips", []) or []:
            is_new = ip not in known_ips
            item = IocItem(type="ip", value=ip, batch_id=batch_id, is_new=is_new)
            all_items.append(item)
            if is_new:
                new_items.append(item)
                self._add_known_ioc("ip", ip)

        for domain in raw.get("domains", []) or []:
            is_new = domain not in known_domains
            item = IocItem(type="domain", value=domain, batch_id=batch_id, is_new=is_new)
            all_items.append(item)
            if is_new:
                new_items.append(item)
                self._add_known_ioc("domain", domain)

        for sha256 in raw.get("hashes", []) or []:
            is_new = sha256 not in known_hashes
            meta = hash_details.get(sha256, {"sha256": sha256, "md5": None, "sha1": None})
            item = IocItem(
                type="sha256",
                value=sha256,
                sha256=meta.get("sha256") or sha256,
                md5=meta.get("md5"),
                sha1=meta.get("sha1"),
                batch_id=batch_id,
                is_new=is_new,
            )
            all_items.append(item)
            if is_new:
                new_items.append(item)
                self._add_known_ioc("sha256", sha256)

        for path in raw.get("droppedFilePath", []) or []:
            is_new = path not in known_paths
            file_name = None
            if path:
                if '\\' in path:
                    file_name = path.rsplit('\\', 1)[-1]
                elif '/' in path:
                    file_name = path.rsplit('/', 1)[-1]
                else:
                    file_name = path
            item = IocItem(
                type="file_path",
                value=path,
                file_path=path,
                file_name=file_name,
                batch_id=batch_id,
                is_new=is_new,
            )
            all_items.append(item)
            if is_new:
                new_items.append(item)
                self._add_known_ioc("file_path", path)

        return all_items, new_items

    def normalize(self, batch: IOCBatch) -> dict:
        """Normalize IOC batch to bulletin dict (new IOCs only)."""
        fetched_at = now_utc_iso()

        title = f"银狐IOC情报 批次#{batch.batch_id}"

        summary_parts = []
        if batch.new_ips:
            summary_parts.append(f"{len(batch.new_ips)}个IP")
        if batch.new_domains:
            summary_parts.append(f"{len(batch.new_domains)}个域名")
        if batch.new_hashes:
            summary_parts.append(f"{len(batch.new_hashes)}个样本")
        if batch.new_file_paths:
            summary_parts.append(f"{len(batch.new_file_paths)}个路径")

        summary = f"银狐恶意软件IOC情报新增: {', '.join(summary_parts)}。数据时间: {batch.update_time.strftime('%Y-%m-%d %H:%M')} UTC"

        body_text = generate_markdown_content(batch)

        published_at = parse_first(
            [(batch.update_time, "api.updateTime")],
            default_tz="Asia/Shanghai",
        )

        labels = ["threatbook", "silverfox", "ioc", "threat_intelligence"]
        if batch.new_ips:
            labels.append("ioc:ip")
        if batch.new_domains:
            labels.append("ioc:domain")
        if batch.new_hashes:
            labels.append("ioc:hash")
        if batch.new_file_paths:
            labels.append("ioc:filepath")

        topics = ["threat_intelligence", "malware", "ioc"]

        extra: Dict[str, Any] = {
            "batch_id": batch.batch_id,
            "update_time": batch.update_time.isoformat(),
            "update_time_ms": batch.update_time_ms,
            "stats": {
                "new_ips": len(batch.new_ips),
                "new_domains": len(batch.new_domains),
                "new_hashes": len(batch.new_hashes),
                "new_file_paths": len(batch.new_file_paths),
                "total_new": len(batch.new_items),
            },
            "ips": [{"value": i.value} for i in batch.new_ips],
            "domains": [{"value": i.value} for i in batch.new_domains],
            "hashes": [
                {"sha256": i.sha256, "md5": i.md5, "sha1": i.sha1}
                for i in batch.new_hashes
            ],
            "file_paths": [
                {"path": i.file_path, "file_name": i.file_name}
                for i in batch.new_file_paths
            ],
        }

        return {
            "source": {
                "source_slug": SOURCE_SLUG,
                "external_id": f"silverfox-ioc-{batch.batch_id}",
                "origin_url": DETAIL_PAGE_URL,
            },
            "content": {
                "title": title,
                "summary": summary,
                "body_text": body_text,
                "published_at": published_at,
                "language": "zh-CN",
            },
            "severity": "high",
            "fetched_at": fetched_at,
            "labels": labels,
            "topics": topics,
            "extra": extra,
            "raw": batch.raw,
        }

    def collect(self, enrich_hashes: bool = True, hash_delay: float = 1.0) -> Tuple[List[dict], Dict[str, Any]]:
        """Collect and normalize IOC data."""
        from zoneinfo import ZoneInfo
        beijing_tz = ZoneInfo("Asia/Shanghai")
        batch_id = datetime.now(beijing_tz).strftime("%Y%m%d%H%M%S")

        stats: Dict[str, Any] = {
            "batch_id": batch_id,
            "items_processed": 0,
            "items_created": 0,
            "new_ips": 0,
            "new_domains": 0,
            "new_hashes": 0,
            "new_file_paths": 0,
            "total_new": 0,
            "hashes_enriched": 0,
            "hashes_from_cache": 0,
        }

        raw = self.fetch_hot_ioc()
        if not raw:
            logger.error("[SilverFox IOC] Failed to fetch IOC data")
            return [], stats

        update_time_ms = raw.get("updateTime", int(time.time() * 1000))
        update_time = datetime.fromtimestamp(update_time_ms / 1000, tz=timezone.utc)

        logger.info(
            "[SilverFox IOC] Batch %s: %d IPs, %d domains, %d hashes, %d paths",
            batch_id,
            len(raw.get("ips", [])),
            len(raw.get("domains", [])),
            len(raw.get("hashes", [])),
            len(raw.get("droppedFilePath", [])),
        )

        known_hashes = self._get_known_iocs("sha256")
        raw_hashes = raw.get("hashes", []) or []
        new_sha256_list = [h for h in raw_hashes if h not in known_hashes]

        logger.info("[SilverFox IOC] New hashes to enrich: %d/%d", len(new_sha256_list), len(raw_hashes))

        hash_details: Dict[str, Dict[str, Optional[str]]] = {}
        if enrich_hashes and new_sha256_list:
            hash_details = self.enrich_new_hashes(new_sha256_list, delay=hash_delay)
            stats["hashes_enriched"] = sum(1 for h in hash_details.values() if h.get("md5"))

        for sha256 in raw_hashes:
            if sha256 not in hash_details:
                cached = self.cache.get("hash_lookups", {}).get(sha256)
                if cached:
                    hash_details[sha256] = {
                        "sha256": sha256,
                        "md5": cached.get("md5"),
                        "sha1": cached.get("sha1"),
                    }
                    stats["hashes_from_cache"] += 1
                else:
                    hash_details[sha256] = {"sha256": sha256, "md5": None, "sha1": None}

        all_items, new_items = self.build_items(raw, hash_details, batch_id)

        stats["items_processed"] = len(all_items)
        stats["new_ips"] = sum(1 for i in new_items if i.type == "ip")
        stats["new_domains"] = sum(1 for i in new_items if i.type == "domain")
        stats["new_hashes"] = sum(1 for i in new_items if i.type == "sha256")
        stats["new_file_paths"] = sum(1 for i in new_items if i.type == "file_path")
        stats["total_new"] = len(new_items)

        self.cache["last_batch_id"] = batch_id
        save_cache(self.cache_path, self.cache)

        if not new_items:
            logger.info(
                "[SilverFox IOC] Batch %s: No new IOCs found, skipping bulletin creation",
                batch_id,
            )
            stats["items_created"] = 0
            return [], stats

        batch = IOCBatch(
            batch_id=batch_id,
            update_time=update_time,
            update_time_ms=update_time_ms,
            items=all_items,
            new_items=new_items,
            raw=raw,
        )

        bulletin = self.normalize(batch)
        stats["items_created"] = 1

        logger.info(
            "[SilverFox IOC] Batch %s completed: %d new IOCs (IP:%d, Domain:%d, Hash:%d, Path:%d)",
            batch_id, stats["total_new"], stats["new_ips"],
            stats["new_domains"], stats["new_hashes"], stats["new_file_paths"],
        )

        return [bulletin], stats


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

    collector = ThreatBookSilverFoxIOCCollector()
    bulletins, stats = collector.collect()

    if not bulletins:
        logger.info("No new IOCs to push (stats: %s)", stats)
        return

    result = push_to_seclens(bulletins)
    print(f"Done: {stats.get('total_new', 0)} new IOCs, {result.get('accepted', 0)} accepted, {result.get('duplicates', 0)} duplicates")


if __name__ == "__main__":
    main()
