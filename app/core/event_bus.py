"""
Thread-safe publish-subscribe Event Bus for CryptoShield.

Decouples file monitoring, threat detection, containment, and reporting subsystems.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List

from app.core.logger import get_logger

logger = get_logger("event_bus")


@dataclass
class Event:
    """Generic event emitted across the framework."""
    event_type: str
    data: Dict[str, Any]
    source: str = "system"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


EventHandler = Callable[[Event], None]


class EventBus:
    """In-memory thread-safe event bus."""

    def __init__(self) -> None:
        self._subscribers: Dict[str, List[EventHandler]] = defaultdict(list)
        self._lock = threading.RLock()

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        """Subscribe a callback to a specific event type, or '*' for all events."""
        with self._lock:
            if handler not in self._subscribers[event_type]:
                self._subscribers[event_type].append(handler)
                logger.debug(f"Subscribed {handler.__name__} to event: {event_type}")

    def unsubscribe(self, event_type: str, handler: EventHandler) -> None:
        """Unsubscribe a callback from an event type."""
        with self._lock:
            if handler in self._subscribers[event_type]:
                self._subscribers[event_type].remove(handler)

    def publish(self, event: Event) -> None:
        """Publish an event to all registered subscribers."""
        handlers: List[EventHandler] = []
        with self._lock:
            handlers.extend(self._subscribers.get(event.event_type, []))
            handlers.extend(self._subscribers.get("*", []))

        for handler in handlers:
            try:
                handler(event)
            except Exception as e:
                logger.exception(
                    f"Error invoking handler {handler.__name__} for event {event.event_type}: {e}"
                )

    def clear(self) -> None:
        """Clear all subscribers."""
        with self._lock:
            self._subscribers.clear()


# Global event bus singleton
BUS = EventBus()
