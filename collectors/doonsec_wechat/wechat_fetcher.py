"""WeChat article fetcher for optional full-content extraction."""
from __future__ import annotations

import logging
import os
import re
import shutil
import time
from contextlib import suppress

from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

try:
    from selenium_stealth import stealth

    HAS_STEALTH = True
except ImportError:
    HAS_STEALTH = False

try:
    from webdriver_manager.chrome import ChromeDriverManager

    HAS_WEBDRIVER_MANAGER = True
except ImportError:
    HAS_WEBDRIVER_MANAGER = False

logger = logging.getLogger(__name__)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


class WeChatFetcher:
    """Fetches WeChat article content using Selenium."""

    def __init__(self, *, proxy_url: str | None = None) -> None:
        self.proxy_url = proxy_url
        self.driver: webdriver.Chrome | None = None

    def _create_driver(self) -> webdriver.Chrome:
        options = webdriver.ChromeOptions()

        if self.proxy_url:
            logger.info("[DOONSEC] browser proxy enabled: %s", self.proxy_url)
            options.add_argument(f"--proxy-server={self.proxy_url}")

        # Prevent Selenium local loopback from being proxied.
        saved_proxy_vars: dict[str, str] = {}
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            if key in os.environ:
                saved_proxy_vars[key] = os.environ.pop(key)

        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-extensions")
        options.add_argument("--window-size=1920,1080")
        options.add_argument(f"user-agent={USER_AGENT}")
        options.add_experimental_option("excludeSwitches", ["enable-automation", "enable-logging"])
        options.add_experimental_option("useAutomationExtension", False)
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument("--disable-logging")
        options.add_argument("--log-level=3")

        chrome_path = os.environ.get("CHROME_BINARY_PATH")
        if chrome_path and os.path.exists(chrome_path):
            options.binary_location = chrome_path

        driver_path = os.environ.get("CHROME_DRIVER_PATH") or shutil.which("chromedriver")
        if driver_path:
            service = Service(driver_path)
        elif HAS_WEBDRIVER_MANAGER:
            service = Service(ChromeDriverManager().install())
        else:
            raise RuntimeError("ChromeDriver not found and webdriver_manager is unavailable")

        try:
            driver = webdriver.Chrome(service=service, options=options)
        finally:
            for key, value in saved_proxy_vars.items():
                os.environ[key] = value

        driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")

        if HAS_STEALTH:
            stealth(
                driver,
                languages=["zh-CN", "zh", "en-US", "en"],
                vendor="Google Inc.",
                platform="Win32",
                webgl_vendor="Intel Inc.",
                renderer="Intel Iris OpenGL Engine",
                fix_hairline=True,
            )

        return driver

    def _ensure_driver(self) -> webdriver.Chrome:
        if self.driver is None:
            self.driver = self._create_driver()
        return self.driver

    def close(self) -> None:
        if self.driver:
            with suppress(Exception):
                self.driver.quit()
            self.driver = None

    def __enter__(self) -> WeChatFetcher:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    @staticmethod
    def extract_content(html: str) -> tuple[str | None, str | None, dict]:
        soup = BeautifulSoup(html, "html.parser")
        metadata: dict = {}

        title: str | None = None
        title_elem = soup.find("h1", class_="rich_media_title")
        if title_elem:
            title = title_elem.get_text(strip=True)
        else:
            meta_title = soup.find("meta", property="og:title")
            if meta_title and meta_title.get("content"):
                title = meta_title["content"]
        metadata["title"] = title

        author_elem = soup.find("span", class_="rich_media_meta rich_media_meta_nickname")
        if author_elem:
            a_tag = author_elem.find("a")
            if a_tag:
                metadata["author"] = a_tag.get_text(strip=True)

        publish_time_elem = soup.find("em", id="publish_time")
        if publish_time_elem:
            metadata["publish_time"] = publish_time_elem.get_text(strip=True)

        body_text: str | None = None
        content_elem = soup.find("div", id="js_content") or soup.find("div", class_="rich_media_content")
        if content_elem:
            body_text = content_elem.get_text(separator="\n", strip=True)
            body_text = re.sub(r"\n{3,}", "\n\n", body_text)
            body_text = re.sub(r"[ \t]+", " ", body_text).strip()

        metadata["content_length"] = len(body_text) if body_text else 0
        return title, body_text, metadata

    def fetch(self, url: str, *, timeout: int = 30) -> tuple[str | None, str | None, dict]:
        try:
            driver = self._ensure_driver()
            driver.get(url)

            wait = WebDriverWait(driver, timeout)
            try:
                wait.until(EC.presence_of_element_located((By.ID, "js_content")))
            except TimeoutException:
                try:
                    wait.until(EC.presence_of_element_located((By.CLASS_NAME, "rich_media_content")))
                except TimeoutException:
                    logger.warning("[DOONSEC] content selector timeout for %s", url)

            time.sleep(1)
            html = driver.page_source

            if "请在微信客户端打开链接" in html:
                return None, None, {"error": "requires_wechat_client"}
            if "该内容已被发布者删除" in html:
                return None, None, {"error": "article_deleted"}

            return self.extract_content(html)
        except WebDriverException as exc:
            logger.error("[DOONSEC] webdriver error for %s: %s", url, exc)
            self.close()
            return None, None, {"error": str(exc)}
        except Exception as exc:
            logger.error("[DOONSEC] fetch error for %s: %s", url, exc)
            return None, None, {"error": str(exc)}
