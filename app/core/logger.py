"""
Structured application logging for CryptoShield.

Provides thread-safe, colored console logs, rotating file logs, and
machine-readable JSONL logs for auditing and incident tracking.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional

# ANSI colors for console output
_COLORS = {
    logging.DEBUG: "\033[36m",     # Cyan
    logging.INFO: "\033[32m",      # Green
    logging.WARNING: "\033[33m",   # Yellow
    logging.ERROR: "\033[31m",     # Red
    logging.CRITICAL: "\033[35m",  # Magenta
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


class ColoredConsoleFormatter(logging.Formatter):
    """Formats log records with ANSI colors and clear readable layout."""

    def format(self, record: logging.LogRecord) -> str:
        color = _COLORS.get(record.levelno, "")
        timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        level_label = f"{color}{_BOLD}[{record.levelname:<8}]{_RESET}"
        name_label = f"\033[90m{record.name}\033[0m"
        message = record.getMessage()

        # Append extra attributes if provided
        extras = {
            k: v for k, v in record.__dict__.items()
            if k not in logging.LogRecord("", 0, "", 0, "", (), None).__dict__
            and not k.startswith("_")
        }
        extra_str = f" \033[90m{json.dumps(extras)}\033[0m" if extras else ""

        return f"{timestamp} {level_label} {name_label}: {message}{extra_str}"


class JsonLineFormatter(logging.Formatter):
    """Formats log records as structured single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
            "thread_name": record.threadName,
        }

        # Include custom extra fields
        for k, v in record.__dict__.items():
            if (
                k not in logging.LogRecord("", 0, "", 0, "", (), None).__dict__
                and not k.startswith("_")
            ):
                payload[k] = v

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload)


_LOGGING_INITIALIZED = False


def setup_logging(
    log_dir: Optional[Path] = None,
    console_level: int = logging.INFO,
    file_level: int = logging.DEBUG,
) -> None:
    """Initialize structured logging handlers for CryptoShield."""
    global _LOGGING_INITIALIZED
    if _LOGGING_INITIALIZED:
        return

    from app.config import CONFIG

    target_dir = log_dir or CONFIG.LOGS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger("cryptoshield")
    root_logger.setLevel(logging.DEBUG)
    root_logger.handlers.clear()

    # 1. Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    console_handler.setFormatter(ColoredConsoleFormatter())
    root_logger.addHandler(console_handler)

    # 2. Text Rotating File Handler (5 MB max, 3 backups)
    text_log_file = target_dir / CONFIG.LOG_FILENAME
    text_handler = RotatingFileHandler(
        text_log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    text_handler.setLevel(file_level)
    text_fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] [%(name)s:%(lineno)d] %(message)s"
    )
    text_handler.setFormatter(text_fmt)
    root_logger.addHandler(text_handler)

    # 3. JSONL Rotating File Handler (10 MB max, 3 backups)
    json_log_file = target_dir / CONFIG.JSON_LOG_FILENAME
    json_handler = RotatingFileHandler(
        json_log_file, maxBytes=10 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    json_handler.setLevel(file_level)
    json_handler.setFormatter(JsonLineFormatter())
    root_logger.addHandler(json_handler)

    _LOGGING_INITIALIZED = True
    root_logger.debug("Structured logging initialized successfully.")


def get_logger(name: str) -> logging.Logger:
    """Retrieve a namespaced child logger under 'cryptoshield'."""
    if not _LOGGING_INITIALIZED:
        setup_logging()
    if name.startswith("cryptoshield.") or name == "cryptoshield":
        return logging.getLogger(name)
    return logging.getLogger(f"cryptoshield.{name}")
