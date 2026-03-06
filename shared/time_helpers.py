"""Lightweight time parsing helpers for standalone collectors.

Provides simple timestamp parsing and normalization without any SecLens
server dependencies. All functions return ISO 8601 strings (UTC).

Usage:
    from shared.time_helpers import parse_datetime

    iso_str = parse_datetime("2025-01-01 09:00:00", default_tz="Asia/Shanghai")
    # -> "2025-01-01T01:00:00+00:00"
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _get_tz(name: str | None) -> timezone:
    """Get a timezone by IANA name. Falls back to UTC on failure."""
    if not name:
        return timezone.utc
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)  # type: ignore[return-value]
    except (ImportError, KeyError):
        logger.warning("Unknown timezone '%s'; falling back to UTC", name)
        return timezone.utc


def _normalise_iso(text: str) -> str:
    """Normalize common ISO 8601 variants (trailing Z, missing colon in offset)."""
    s = text.strip()
    if s.endswith("Z") or s.endswith("z"):
        s = s[:-1] + "+00:00"
    # +0800 -> +08:00
    for sep in ("+", "-"):
        idx = s.rfind(sep)
        if idx > 10:  # after date portion
            offset = s[idx + 1:]
            if len(offset) == 4 and offset.isdigit():
                s = s[:idx + 1] + offset[:2] + ":" + offset[2:]
                break
    return s


def _parse_rfc2822(text: str) -> datetime | None:
    """Try to parse RFC 2822 date (common in RSS feeds)."""
    try:
        return parsedate_to_datetime(text.strip())
    except (TypeError, ValueError, IndexError):
        return None


def _parse_iso(text: str) -> datetime | None:
    """Try to parse ISO 8601 date string."""
    try:
        return datetime.fromisoformat(_normalise_iso(text))
    except ValueError:
        return None


def _parse_timestamp(value: float | int) -> datetime:
    """Parse a numeric timestamp (seconds or milliseconds) to UTC datetime."""
    seconds = float(value)
    if seconds > 1e12:
        seconds /= 1000.0
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def parse_datetime(
    value: Any,
    *,
    default_tz: str | None = None,
) -> str | None:
    """Parse a timestamp value into an ISO 8601 UTC string.

    Supports:
    - datetime objects
    - ISO 8601 strings (with or without timezone)
    - RFC 2822 strings (RSS pubDate format)
    - Unix timestamps (seconds or milliseconds)

    Args:
        value: The timestamp to parse (str, int, float, datetime, or None).
        default_tz: IANA timezone name to assume for naive timestamps.
                    Defaults to UTC if not provided.

    Returns:
        ISO 8601 string in UTC, or None if parsing fails.
    """
    if value is None:
        return None

    dt: datetime | None = None

    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        dt = _parse_timestamp(value)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        # Try RFC 2822 first (RSS), then ISO 8601, then numeric
        dt = _parse_rfc2822(text) or _parse_iso(text)
        if dt is None and text.isdigit():
            try:
                dt = _parse_timestamp(float(text))
            except (ValueError, OverflowError):
                return None

    if dt is None:
        return None

    # Apply default timezone if naive
    if dt.tzinfo is None:
        tz = _get_tz(default_tz)
        dt = dt.replace(tzinfo=tz)

    # Convert to UTC
    return dt.astimezone(timezone.utc).isoformat()


def parse_first(
    candidates: list[tuple[Any, str | None]],
    *,
    default_tz: str | None = None,
) -> str | None:
    """Try multiple candidate values and return the first successful parse.

    Args:
        candidates: List of (value, label) tuples to try in order.
        default_tz: Default timezone for naive timestamps.

    Returns:
        ISO 8601 UTC string from the first successful candidate, or None.
    """
    for value, _label in candidates:
        result = parse_datetime(value, default_tz=default_tz)
        if result:
            return result
    return None


def now_utc_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()
