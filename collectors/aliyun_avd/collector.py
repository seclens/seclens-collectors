"""Aliyun AVD (Vulnerability Database) Collector (standalone).

Collects vulnerability information from Aliyun's AVD using Selenium to
bypass WAF anti-crawling mechanisms.

Usage:
    export SECLENS_URL="https://your-seclens-server.com"
    export SECLENS_TOKEN="your-api-token"
    python collector.py

Schedule: recommended every 4 hours (14400s)
"""
# ruff: noqa: UP006,UP035,UP045,UP015,UP017,SIM105,F541,I001
from __future__ import annotations

import json
import logging
import os
import re
import stat
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException
from selenium_stealth import stealth

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

SOURCE_SLUG = "aliyun_avd"
USER_AGENT = "SeclensCollector/2.0 (aliyun_avd)"
REQUEST_TIMEOUT = 30

CACHE_FILE = ".cursor"
CACHE_LIMIT = 100
CACHE_DAYS = 180
MAX_AGE_DAYS = 60
BASE_URL = "https://avd.aliyun.com"
LIST_URL = BASE_URL
DETAIL_URL_TEMPLATE = f"{BASE_URL}/detail?id={{avd_id}}"
MANIFEST, MANIFEST_HASH, MANIFEST_VERSION = load_manifest_for_slug(SOURCE_SLUG)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(SOURCE_SLUG)


# ---------------------------------------------------------------------------
# Cache Management
# ---------------------------------------------------------------------------


def load_cache() -> Dict[str, Any]:
    """Loads the cache from the JSON file."""
    cache_path = Path(__file__).parent / CACHE_FILE
    try:
        with open(cache_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_cache(cache_data: Dict[str, Any]) -> None:
    """Saves the cache to the JSON file."""
    cache_path = Path(__file__).parent / CACHE_FILE
    with open(cache_path, 'w', encoding='utf-8') as f:
        json.dump(cache_data, f, ensure_ascii=False, indent=2)


def trim_cache(cache_data: dict, limit: int = CACHE_LIMIT) -> dict:
    """Trim cache to retain only the most recent `limit` entries."""
    if not cache_data or limit <= 0:
        return {}

    def sort_key(item):
        data = item[1] or {}
        timestamp = data.get("_cached_at")
        if timestamp:
            try:
                return datetime.fromisoformat(timestamp)
            except ValueError:
                return datetime.min
        return datetime.min

    sorted_items = sorted(cache_data.items(), key=sort_key, reverse=True)
    trimmed_items = sorted_items[:limit]

    if len(sorted_items) > limit:
        logger.info(f"[CACHE] Trimmed cache from {len(sorted_items)} to {limit} entries")

    return dict(trimmed_items)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _clean_text(text: str | None) -> str | None:
    """Clean and normalize text."""
    if not text:
        return None
    text = text.strip()
    text = re.sub(r'\s+', ' ', text)
    return text or None


def parse_list_page(html: str) -> List[Dict[str, str]]:
    """Parse the list page and extract AVD IDs with time filtering."""
    soup = BeautifulSoup(html, 'html.parser')
    vulnerabilities = []
    filtered_count = 0

    cutoff_date = datetime.now() - timedelta(days=MAX_AGE_DAYS)

    table = soup.find('table', class_='table')
    if not table:
        logger.warning("Vulnerability list table not found")
        return vulnerabilities

    tbody = table.find('tbody')
    if not tbody:
        return vulnerabilities

    for row in tbody.find_all('tr'):
        cells = row.find_all('td')
        if len(cells) < 5:
            continue

        avd_link = cells[0].find('a')
        if not avd_link:
            continue

        avd_id = _clean_text(avd_link.get_text())
        if not avd_id or not avd_id.startswith('AVD-'):
            continue

        published_date_str = _clean_text(cells[3].get_text()) if len(cells) > 3 else ''

        if published_date_str:
            try:
                pub_date = datetime.strptime(published_date_str, '%Y-%m-%d')
                if pub_date < cutoff_date:
                    logger.debug(f"Skipping old vulnerability (>{MAX_AGE_DAYS} days): {avd_id} ({published_date_str})")
                    filtered_count += 1
                    continue
            except ValueError:
                logger.warning(f"Cannot parse date format: {published_date_str}")

        vuln_data = {
            'avd_id': avd_id,
            'title': _clean_text(cells[1].get_text()) if len(cells) > 1 else '',
            'cwe_type': _clean_text(cells[2].get_text()) if len(cells) > 2 else '',
            'published_date': published_date_str,
        }

        vulnerabilities.append(vuln_data)

    logger.info(f"Extracted {len(vulnerabilities)} vulnerabilities from list page (filtered {filtered_count} old ones)")
    return vulnerabilities


def parse_detail_page(html: str, avd_id: str) -> Optional[Dict[str, Any]]:
    """Parse the detail page and extract full vulnerability information."""
    soup = BeautifulSoup(html, 'html.parser')
    data = {'avd_id': avd_id}

    title_elem = soup.find('span', class_='header__title__text')
    if title_elem:
        data['title'] = _clean_text(title_elem.get_text())

    severity_badge = soup.find('span', class_='badge')
    if severity_badge:
        data['severity'] = _clean_text(severity_badge.get_text())

    metrics = soup.find_all('div', class_='metric')
    for metric in metrics:
        label_elem = metric.find('p', class_='metric-label')
        value_elem = metric.find('div', class_='metric-value')

        if label_elem and value_elem:
            label = _clean_text(label_elem.get_text())
            value = _clean_text(value_elem.get_text())

            if label == 'CVE编号':
                data['cve_id'] = value
            elif label == '利用情况':
                data['exploit_status'] = value
            elif label == '补丁情况':
                data['patch_status'] = value
            elif label == '披露时间':
                data['published_date'] = value

    desc_sections = soup.find_all('div', class_='text-detail')
    if len(desc_sections) >= 1:
        data['description'] = _clean_text(desc_sections[0].get_text())

    if len(desc_sections) >= 2:
        data['solution'] = _clean_text(desc_sections[1].get_text())

    references = []
    ref_table = soup.find('table', class_='table-sm')
    if ref_table:
        for link in ref_table.find_all('a'):
            href = link.get('href')
            if href and href.startswith('http'):
                references.append(href)
    data['references'] = references

    cvss_score_elem = soup.find('div', class_='cvss-breakdown__score')
    if cvss_score_elem:
        score_text = _clean_text(cvss_score_elem.get_text())
        try:
            data['aliyun_score'] = float(score_text)
        except (ValueError, TypeError):
            pass

    cvss_items = soup.find_all('li', class_='cvss-breakdown__item')
    cvss_details = {}
    for item in cvss_items:
        title_elem = item.find('div', class_='cvss-breakdown__title')
        desc_elem = item.find('div', class_='cvss-breakdown__desc')

        if title_elem and desc_elem:
            for i_tag in title_elem.find_all('i'):
                i_tag.decompose()

            title = _clean_text(title_elem.get_text())
            desc = _clean_text(desc_elem.get_text())

            if title and desc:
                cvss_details[title] = desc

    if cvss_details:
        data['cvss_details'] = cvss_details

    for table in soup.find_all('table', class_='table'):
        thead = table.find('thead')
        if thead and 'CWE-ID' in thead.get_text():
            tbody = table.find('tbody')
            if tbody:
                for row in tbody.find_all('tr'):
                    cells = row.find_all('td')
                    if len(cells) >= 2:
                        cwe_id = _clean_text(cells[0].get_text())
                        cwe_desc = _clean_text(cells[1].get_text())
                        if cwe_id and cwe_id.startswith('CWE-'):
                            data['cwe_id'] = cwe_id
                            data['cwe_description'] = cwe_desc
                            break
            break

    return data


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class AliyunAVDCollector:
    """Aliyun AVD vulnerability collector (Selenium-based)."""

    def __init__(self) -> None:
        self.driver = None
        self.cache = load_cache()

    def create_driver(self) -> webdriver.Chrome:
        """Create and configure Chrome WebDriver."""
        options = webdriver.ChromeOptions()

        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-plugins-discovery")
        options.add_argument("--disable-background-timer-throttling")
        options.add_argument("--disable-backgrounding-occluded-windows")
        options.add_argument("--disable-renderer-backgrounding")
        options.add_argument("--no-first-run")
        options.add_argument("--no-default-browser-check")
        options.add_argument("--disable-default-apps")
        options.add_argument("--disable-features=Translate")
        options.add_argument("--disable-ipc-flooding-protection")
        options.add_argument("--disable-component-extensions-with-background-pages")

        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_experimental_option("excludeSwitches", ["enable-automation", "enable-logging"])
        options.add_experimental_option("useAutomationExtension", False)
        options.add_argument("--disable-logging")
        options.add_argument("--log-level=3")

        options.add_argument("--user-agent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")

        chrome_binary_path = os.environ.get("CHROME_BINARY_PATH")
        chrome_driver_path = os.environ.get("CHROME_DRIVER_PATH")

        if chrome_binary_path and os.path.exists(chrome_binary_path):
            options.binary_location = chrome_binary_path
            logger.info(f"Using custom Chrome binary: {chrome_binary_path}")

        if chrome_driver_path and os.path.exists(chrome_driver_path):
            if not os.access(chrome_driver_path, os.X_OK):
                logger.info(f"Setting ChromeDriver execute permission: {chrome_driver_path}")
                current_permissions = os.stat(chrome_driver_path).st_mode
                os.chmod(chrome_driver_path, current_permissions | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            service = Service(chrome_driver_path)
        else:
            logger.info("Using webdriver-manager to auto-download ChromeDriver")
            driver_path = ChromeDriverManager().install()
            service = Service(driver_path)

        driver = webdriver.Chrome(service=service, options=options)

        driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")

        stealth(
            driver,
            languages=["zh-CN", "zh", "en-US", "en"],
            vendor="Google Inc.",
            platform="Win32",
            webgl_vendor="Intel Inc.",
            renderer="Intel Iris OpenGL Engine",
            fix_hairline=True,
            extra_options={
                "app": "Chrome Apps Package Loader",
                "appName": "Apps Package Loader",
                "appVersion": "2.4.4.29",
                "platform": "MacIntel"
            }
        )

        driver.set_page_load_timeout(30)
        return driver

    def close_driver(self) -> None:
        """Close WebDriver."""
        if self.driver:
            try:
                self.driver.quit()
            except Exception as e:
                logger.warning(f"Failed to close WebDriver: {e}")
            finally:
                self.driver = None

    def fetch_list_page(self) -> str:
        """Fetch list page HTML using Selenium."""
        if not self.driver:
            self.driver = self.create_driver()

        try:
            logger.info(f"Visiting list page: {LIST_URL}")
            self.driver.get(LIST_URL)

            wait = WebDriverWait(self.driver, 30)
            wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "table.table")))

            time.sleep(2)

            html = self.driver.page_source
            logger.info(f"Successfully fetched list page, HTML length: {len(html)}")
            return html

        except TimeoutException:
            logger.warning("Timed out waiting for table to load, returning current page source")
            return self.driver.page_source
        except Exception as e:
            logger.error(f"Failed to fetch list page: {e}")
            raise

    def fetch_detail_page(self, avd_id: str, link_element=None) -> str:
        """Fetch detail page HTML by clicking link or direct URL."""
        if not self.driver:
            self.driver = self.create_driver()

        try:
            main_window = self.driver.current_window_handle

            if link_element:
                logger.debug(f"Clicking link to detail page: {avd_id}")
                link_element.click()
                time.sleep(2)

                windows = self.driver.window_handles
                if len(windows) > 1:
                    new_window = [w for w in windows if w != main_window][0]
                    self.driver.switch_to.window(new_window)
                    logger.debug(f"Switched to new window")
            else:
                url = DETAIL_URL_TEMPLATE.format(avd_id=avd_id)
                logger.warning(f"Using direct URL to visit detail page (may be unstable): {url}")
                self.driver.get(url)

            time.sleep(3)

            wait = WebDriverWait(self.driver, 10)
            try:
                wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "span.header__title__text")))
                logger.debug(f"Detail page {avd_id} title element loaded")
            except TimeoutException:
                logger.warning(f"Detail page {avd_id} timed out waiting for title element")

            time.sleep(2)

            html = self.driver.page_source
            html_len = len(html)

            if html_len == 0:
                logger.error(f"Detail page {avd_id} page_source is empty!")
                try:
                    current_url = self.driver.current_url
                    page_title = self.driver.title
                    logger.error(f"Current URL: {current_url}, title: {page_title}")
                except Exception as e:
                    logger.error(f"Cannot get driver state: {e}")
                return html

            is_valid = self._validate_detail_html(html, avd_id)

            if is_valid:
                logger.debug(f"Detail page {avd_id} HTML validated, length: {html_len}")
            else:
                logger.warning(f"Detail page {avd_id} HTML validation failed, length: {html_len}")

            windows = self.driver.window_handles
            if len(windows) > 1:
                logger.debug("Closing detail page tab")
                self.driver.close()
                self.driver.switch_to.window(main_window)

            return html

        except Exception as e:
            logger.error(f"Failed to fetch detail page {avd_id}: {e}")
            try:
                windows = self.driver.window_handles
                if len(windows) > 1:
                    self.driver.close()
                main_window = self.driver.window_handles[0]
                self.driver.switch_to.window(main_window)
            except Exception as recovery_error:
                logger.error(f"Failed to recover main window: {recovery_error}")
            raise

    def _validate_detail_html(self, html: str, avd_id: str) -> bool:
        """Validate detail page HTML content quality."""
        if not html:
            logger.warning(f"Detail page {avd_id} HTML is empty")
            return False

        html_len = len(html)
        if html_len < 500:
            logger.warning(f"Detail page {avd_id} HTML too short: {html_len} chars")
            return False

        soup = BeautifulSoup(html, 'html.parser')

        required_elements = {
            'metric': soup.find_all('div', class_='metric'),
            'card_content': soup.find_all('div', class_='card__content'),
            'text_detail': soup.find_all('div', class_='text-detail'),
            'cvss_score': soup.find('div', class_='cvss-breakdown__score'),
        }

        required_keywords = ['攻击路径', '漏洞描述', '阿里云评分', '披露时间']
        found_keywords = [kw for kw in required_keywords if kw in html]

        has_metrics = len(required_elements['metric']) > 0
        has_description = len(required_elements['text_detail']) > 0
        has_score = required_elements['cvss_score'] is not None
        has_keywords = len(found_keywords) >= 3

        if has_metrics and has_description and has_score and has_keywords:
            return True

        missing_features = []
        if not has_metrics:
            missing_features.append("metrics(div.metric)")
        if not has_description:
            missing_features.append("description(div.text-detail)")
        if not has_score:
            missing_features.append("score(div.cvss-breakdown__score)")
        if not has_keywords:
            missing_keywords = [kw for kw in required_keywords if kw not in html]
            missing_features.append(f"keywords({', '.join(missing_keywords)})")

        logger.warning(f"Detail page {avd_id} validation failed - missing: {', '.join(missing_features)}")
        return False

    def normalize(self, vuln_data: Dict[str, Any]) -> dict:
        """Convert vulnerability data to a bulletin dict."""
        avd_id = vuln_data.get('avd_id', '')
        title = vuln_data.get('title', avd_id)

        origin_url = DETAIL_URL_TEMPLATE.format(avd_id=avd_id)

        fetched_at = now_utc_iso()
        published_date_str = vuln_data.get('published_date')
        published_at = parse_first(
            [(published_date_str, "published_date")],
            default_tz="Asia/Shanghai",
        )

        severity_map = {
            '严重': 'critical',
            '高危': 'high',
            '中危': 'medium',
            '低危': 'low',
        }
        severity_text = vuln_data.get('severity', '高危')
        severity = severity_map.get(severity_text, 'high')

        description_parts = []
        if vuln_data.get('description'):
            description_parts.append(vuln_data['description'])

        metrics = []
        if vuln_data.get('cve_id'):
            metrics.append(f"CVE编号: {vuln_data['cve_id']}")
        if vuln_data.get('exploit_status'):
            metrics.append(f"利用情况: {vuln_data['exploit_status']}")
        if vuln_data.get('patch_status'):
            metrics.append(f"补丁情况: {vuln_data['patch_status']}")
        if vuln_data.get('aliyun_score'):
            metrics.append(f"阿里云评分: {vuln_data['aliyun_score']}")

        if metrics:
            description_parts.append('\n\n' + '\n'.join(metrics))

        if vuln_data.get('cvss_details'):
            cvss_lines = ['\n\n** 威胁评估 **']
            for key, value in vuln_data['cvss_details'].items():
                cvss_lines.append(f"{key}: {value}")
            description_parts.append('\n'.join(cvss_lines))

        if vuln_data.get('solution'):
            description_parts.append(f"\n\n** 解决建议 **\n{vuln_data['solution']}")

        if vuln_data.get('references'):
            ref_lines = ['\n\n** 参考链接 **']
            for ref in vuln_data['references']:
                ref_lines.append(f"- {ref}")
            description_parts.append('\n'.join(ref_lines))

        summary = description_parts[0] if description_parts else title
        body_text = '\n'.join(description_parts)

        labels = []
        if vuln_data.get('cve_id'):
            labels.append(f"cve:{vuln_data['cve_id'].lower()}")
        if vuln_data.get('cwe_id'):
            labels.append(f"cwe:{vuln_data['cwe_id'].lower()}")
        if vuln_data.get('exploit_status'):
            labels.append(f"exploit:{vuln_data['exploit_status'].lower().replace(' ', '_')}")

        is_fallback = vuln_data.get('_fallback', False)
        if is_fallback:
            labels.append("parse-failed")

        extra = {
            'avd_id': avd_id,
            'severity_text': severity_text,
        }

        if vuln_data.get('aliyun_score'):
            extra['aliyun_score'] = vuln_data['aliyun_score']
        if vuln_data.get('cvss_details'):
            extra['cvss_details'] = vuln_data['cvss_details']
        if vuln_data.get('cwe_description'):
            extra['cwe_description'] = vuln_data['cwe_description']

        if is_fallback:
            extra['fallback'] = True
            if vuln_data.get('_html_text'):
                extra['html_text_preview'] = vuln_data['_html_text']

        return {
            "source": {
                "source_slug": SOURCE_SLUG,
                "external_id": avd_id,
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
            "severity": severity,
            "fetched_at": fetched_at,
            "labels": labels,
            "topics": ["vulnerability", "security-advisory"],
            "extra": extra,
            "raw": vuln_data,
        }

    def _create_fallback_data(
        self,
        vuln_summary: Dict[str, Any],
        detail_html: str | None,
    ) -> Dict[str, Any] | None:
        """Create fallback data when detail page parsing fails."""
        avd_id = vuln_summary.get('avd_id')
        if not avd_id:
            return None

        html_text = ""
        if detail_html:
            try:
                soup = BeautifulSoup(detail_html, 'html.parser')
                for script in soup(["script", "style"]):
                    script.decompose()
                html_text = soup.get_text(separator='\n', strip=True)
            except Exception as e:
                logger.warning(f"Failed to extract HTML text: {e}")
                html_text = detail_html[:1000] if detail_html else ""

        fallback_data = {
            'avd_id': avd_id,
            'title': vuln_summary.get('title', f'Aliyun AVD {avd_id}'),
            'published_date': vuln_summary.get('published_date', ''),
            'cwe_type': vuln_summary.get('cwe_type', ''),
            'severity': vuln_summary.get('severity', '未知'),
            'description': f"[Parse failed - fallback data]\n\nList page info:\n{vuln_summary}\n\n",
            'solution': '',
            'references': [],
            '_fallback': True,
            '_html_text': html_text[:2000] if html_text else "",
        }

        if html_text:
            fallback_data['description'] += f"\nOriginal page text excerpt:\n{html_text[:500]}..."

        return fallback_data

    def collect(self, limit: int | None = None) -> Tuple[list[dict], Dict[str, int]]:
        """Collect vulnerability information using Selenium."""
        bulletins = []
        stats = {
            'items_processed': 0,
            'items_created': 0,
            'items_skipped_cache': 0,
            'items_failed': 0,
        }

        try:
            try:
                list_html = self.fetch_list_page()
                vuln_list = parse_list_page(list_html)
            except Exception as e:
                logger.error(f"Failed to fetch list page: {e}")
                return bulletins, stats

            if limit and limit > 0:
                vuln_list = vuln_list[:limit]

            logger.info(f"Processing {len(vuln_list)} vulnerabilities")

            for idx, vuln_summary in enumerate(vuln_list):
                avd_id = vuln_summary['avd_id']
                stats['items_processed'] += 1

                if avd_id in self.cache:
                    logger.debug(f"Skipping cached: {avd_id}")
                    stats['items_skipped_cache'] += 1
                    continue

                link_element = None
                detail_html = None
                vuln_data = None

                try:
                    if self.driver:
                        try:
                            avd_links = self.driver.find_elements(By.CSS_SELECTOR, "table.table tbody tr td a")
                            for link in avd_links:
                                if link.text.strip() == avd_id:
                                    link_element = link
                                    break

                            if not link_element:
                                logger.warning(f"Link element not found on page: {avd_id}, using direct access")
                        except Exception as find_error:
                            logger.warning(f"Failed to find link element: {find_error}, using direct access")

                    detail_html = self.fetch_detail_page(avd_id, link_element)
                    vuln_data = parse_detail_page(detail_html, avd_id)

                    if not vuln_data:
                        logger.warning(f"Detail page parsing failed: {avd_id}, using fallback strategy")
                        vuln_data = self._create_fallback_data(vuln_summary, detail_html)
                        if not vuln_data:
                            stats['items_failed'] += 1
                            continue
                    else:
                        vuln_data.update({
                            k: v for k, v in vuln_summary.items()
                            if k not in vuln_data or not vuln_data.get(k)
                        })

                    bulletin = self.normalize(vuln_data)
                    bulletins.append(bulletin)
                    stats['items_created'] += 1

                    self.cache[avd_id] = {
                        'title': vuln_data.get('title', ''),
                        'published_date': vuln_data.get('published_date', ''),
                        '_cached_at': now_utc_iso(),
                    }

                    logger.info(f"Successfully collected [{idx+1}/{len(vuln_list)}]: {avd_id} - {vuln_data.get('title', '')}")

                except Exception as e:
                    logger.error(f"Failed to process {avd_id}: {e}, trying fallback strategy")
                    try:
                        fallback_data = self._create_fallback_data(vuln_summary, detail_html)
                        if fallback_data:
                            bulletin = self.normalize(fallback_data)
                            bulletins.append(bulletin)
                            stats['items_created'] += 1

                            self.cache[avd_id] = {
                                'title': fallback_data.get('title', ''),
                                'published_date': fallback_data.get('published_date', ''),
                                '_cached_at': now_utc_iso(),
                            }
                            logger.warning(f"Collected with fallback data: {avd_id}")
                        else:
                            stats['items_failed'] += 1
                    except Exception as fallback_error:
                        logger.error(f"Fallback strategy also failed: {avd_id} - {fallback_error}")
                        stats['items_failed'] += 1
                    continue

        finally:
            self.close_driver()

            self.cache = trim_cache(self.cache, CACHE_LIMIT)
            save_cache(self.cache)

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
        timeout=60,
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

    collector = AliyunAVDCollector()
    bulletins, stats = collector.collect()

    if not bulletins:
        logger.info("No new bulletins to push")
        return

    result = push_to_seclens(bulletins)
    logger.info(
        "Done: created=%d, accepted=%s, duplicates=%s",
        stats["items_created"],
        result.get("accepted", 0),
        result.get("duplicates", 0),
    )


if __name__ == "__main__":
    main()
