"""Lightweight helper for pushing bulletins to a SecLens server.

This is an optional convenience module. Collectors can also use requests
(or any HTTP client) directly. See docs/API_CONTRACT.md for the full spec.

Usage:
    from shared.seclens_client import SeclensClient

    client = SeclensClient()  # reads SECLENS_URL and SECLENS_TOKEN from env
    result = client.push([
        {
            "source": {"source_slug": "my_source", "external_id": "123"},
            "content": {"title": "Test"},
        }
    ])
    print(result)  # {"accepted": 1, "duplicates": 0}
"""
from __future__ import annotations

import logging
import os
from typing import Any

import requests

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30
MAX_BATCH_SIZE = 200


class SeclensClient:
    """Minimal HTTP client for the SecLens Ingest API."""

    def __init__(
        self,
        url: str | None = None,
        token: str | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.url = (url or os.environ.get("SECLENS_URL", "")).rstrip("/")
        self.token = token or os.environ.get("SECLENS_TOKEN", "")
        self.timeout = timeout

        if not self.url:
            raise ValueError("SECLENS_URL is required (pass as argument or set env var)")
        if not self.token:
            raise ValueError("SECLENS_TOKEN is required (pass as argument or set env var)")

        self.endpoint = f"{self.url}/v1/ingest/bulletins"
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "User-Agent": "SeclensCollector/2.0",
        })

    def push(self, bulletins: list[dict[str, Any]]) -> dict[str, Any]:
        """Submit bulletins to the SecLens server.

        Args:
            bulletins: List of bulletin dicts matching the Ingest API schema.

        Returns:
            Server response dict, e.g. {"accepted": 5, "duplicates": 2}

        Raises:
            requests.HTTPError: If the server returns a non-2xx status.
            ValueError: If the batch is empty or too large.
        """
        if not bulletins:
            raise ValueError("Empty bulletin list")

        total_accepted = 0
        total_duplicates = 0

        # Split into batches if needed
        for i in range(0, len(bulletins), MAX_BATCH_SIZE):
            batch = bulletins[i : i + MAX_BATCH_SIZE]
            logger.info("Pushing batch of %d bulletins to %s", len(batch), self.endpoint)

            resp = self.session.post(self.endpoint, json=batch, timeout=self.timeout)
            resp.raise_for_status()

            data = resp.json()
            total_accepted += data.get("accepted", 0)
            total_duplicates += data.get("duplicates", 0)

            logger.info(
                "Batch result: accepted=%d, duplicates=%d",
                data.get("accepted", 0),
                data.get("duplicates", 0),
            )

        return {"accepted": total_accepted, "duplicates": total_duplicates}
