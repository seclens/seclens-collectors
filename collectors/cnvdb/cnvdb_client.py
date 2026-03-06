"""HTTP client utilities for the MIIT CNVDB portal."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import logging
import time
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlencode, urlsplit, parse_qsl

import requests

LOGGER = logging.getLogger(__name__)

BASE_URL = "https://cnvdb.org.cn/ld_web"
SECRET = "1e31af8c14999aa99d78537a8641ea4d"
USER_AGENT = "SecLensCNVDBClient/1.0"


def _normalise_items(params: Mapping[str, Any] | Sequence[tuple[str, Any]] | None) -> list[tuple[str, str]]:
    """Coerce params to a sorted list of string tuples."""
    if params is None:
        return []
    items: Iterable[tuple[str, Any]]
    if isinstance(params, Mapping):
        items = params.items()
    else:
        items = params
    normalised: list[tuple[str, str]] = []
    for key, value in items:
        if key is None:
            continue
        str_value = "" if value is None else str(value)
        normalised.append((str(key), str_value))
    return sorted(normalised, key=lambda kv: kv[0])


def _trimmed_values(items: Iterable[tuple[str, str]]) -> list[str]:
    trimmed: list[str] = []
    for _, value in items:
        candidate = value.rstrip()
        if candidate:
            trimmed.append(candidate)
    return trimmed


def _signature_payload(timestamp: int, params: list[tuple[str, str]]) -> str:
    pieces = _trimmed_values(params)
    if pieces:
        return f"{timestamp},{','.join(pieces)},{SECRET}"
    return f"{timestamp},{SECRET}"


def generate_signature(method: str, path: str, params: Mapping[str, Any] | Sequence[tuple[str, Any]] | None = None) -> tuple[str, str]:
    """Generate the anti-scraping signature header value.

    Returns a tuple of the header value and the canonical path with query string.
    """
    method = method.upper()
    timestamp = int(time.time() * 1000)
    if method == "GET":
        normalised = _normalise_items(params)
        if not normalised and "?" in path:
            query = dict(parse_qsl(urlsplit(path).query, keep_blank_values=True))
            normalised = _normalise_items(query)
        payload = _signature_payload(timestamp, normalised)
    else:
        normalised = _normalise_items(params)
        payload = _signature_payload(timestamp, normalised)
    digest = hashlib.md5(payload.encode("utf-8")).hexdigest()
    header_value = f"{timestamp};{digest}"

    path_part = path
    if not path_part.startswith("/"):
        path_part = f"/{path_part}"
    query_string = urlencode(normalised)
    if query_string:
        path_part = f"{path_part}?{query_string}"

    return header_value, path_part


@dataclass
class CNVDBClient:
    """Lightweight client that knows how to sign CNVDB requests."""

    base_url: str = BASE_URL
    session: requests.Session | None = None

    def __post_init__(self) -> None:
        if self.session is None:
            self.session = requests.Session()
        self.session.headers.setdefault("Accept", "application/json;charset=UTF-8")
        self.session.headers.setdefault("Referer", "https://cnvdb.org.cn/")
        self.session.headers.setdefault("User-Agent", USER_AGENT)

    def _request(self, method: str, endpoint: str, params: Mapping[str, Any] | Sequence[tuple[str, Any]] | None = None) -> requests.Response:
        header_value, canonical_path = generate_signature(method, endpoint, params=params)
        headers = {"signature": header_value}

        url = f"{self.base_url.rstrip('/')}{canonical_path}"
        LOGGER.debug("Fetching %s %s", method, url)
        response = self.session.request(method, url, headers=headers, timeout=20)
        response.raise_for_status()
        return response

    def list_policies(self, page: int = 1, page_size: int = 15) -> dict[str, Any]:
        params = {"currentPage": page, "pageSize": page_size}
        response = self._request("GET", "/policy", params=params)
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Unexpected payload from CNVDB list endpoint")
        return payload

    def get_policy_detail(self, policy_id: str) -> dict[str, Any]:
        params = {"id": policy_id}
        response = self._request("GET", "/policy/getById", params=params)
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Unexpected payload from CNVDB detail endpoint")
        return payload


__all__ = ["CNVDBClient", "generate_signature"]
