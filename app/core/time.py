"""
CryptoShield — Timezone & Temporal Synchronization Engine.

Enforces centralized Indian Standard Time (IST, UTC+05:30) synchronization
across all defensive subsystems, telemetry streams, logs, dossiers, and UI consoles.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

# Indian Standard Time (UTC+05:30) offset
IST_OFFSET = timedelta(hours=5, minutes=30)
IST = timezone(IST_OFFSET, name="IST")

# Primary operational timezone constant
DEFAULT_TIMEZONE = IST
DEFAULT_TIMEZONE_NAME = "IST"


def now_ist() -> datetime:
    """Return the current datetime localized in Indian Standard Time (IST)."""
    return datetime.now(IST)


def now_iso() -> str:
    """Return the current ISO-8601 timestamp string localized in IST."""
    return datetime.now(IST).isoformat()


def from_timestamp_ist(ts: float) -> datetime:
    """Convert an epoch float to an IST-localized datetime object."""
    return datetime.fromtimestamp(ts, tz=IST)


def format_ist(dt: Optional[datetime] = None, fmt: str = "%Y-%m-%d %H:%M:%S IST") -> str:
    """Format a datetime in Indian Standard Time (IST)."""
    if dt is None:
        dt = now_ist()
    elif dt.tzinfo is None:
        dt = dt.replace(tzinfo=IST)
    else:
        dt = dt.astimezone(IST)
    return dt.strftime(fmt)


def parse_iso_to_ist(ts_str: str) -> datetime:
    """
    Safely parse an ISO-8601 timestamp string and convert/localize it to IST.
    Supports timestamps with 'Z', explicit offsets, or naive strings.
    """
    if not ts_str:
        return now_ist()
    try:
        clean_ts = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_ts)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=IST)
        return dt.astimezone(IST)
    except Exception:
        return now_ist()
