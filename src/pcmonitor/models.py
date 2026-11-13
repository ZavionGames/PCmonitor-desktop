"""Event types and the JSON shape sent to the web API."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

AGENT_STARTED = "agent_started"
AGENT_STOPPED = "agent_stopped"
SYSTEM_STARTED = "system_started"
SYSTEM_SHUTDOWN = "system_shutdown"
SYSTEM_RESTART = "system_restart"
SYSTEM_UNEXPECTED_SHUTDOWN = "system_unexpected_shutdown"
SYSTEM_SLEEP = "system_sleep"
SYSTEM_RESUME = "system_resume"
SYSTEM_HIBERNATE = "system_hibernate"
SESSION_LOGON = "session_logon"
SESSION_LOGOFF = "session_logoff"
SESSION_LOCK = "session_lock"
SESSION_UNLOCK = "session_unlock"
PROCESS_STARTED = "process_started"
PROCESS_STOPPED = "process_stopped"
TRACKING_PAUSED = "tracking_paused"
TRACKING_RESUMED = "tracking_resumed"

PROCESS_EVENT_TYPES = frozenset({PROCESS_STARTED, PROCESS_STOPPED})

EVENT_TYPES = frozenset(
    {
        AGENT_STARTED,
        AGENT_STOPPED,
        SYSTEM_STARTED,
        SYSTEM_SHUTDOWN,
        SYSTEM_RESTART,
        SYSTEM_UNEXPECTED_SHUTDOWN,
        SYSTEM_SLEEP,
        SYSTEM_RESUME,
        SYSTEM_HIBERNATE,
        SESSION_LOGON,
        SESSION_LOGOFF,
        SESSION_LOCK,
        SESSION_UNLOCK,
        PROCESS_STARTED,
        PROCESS_STOPPED,
        TRACKING_PAUSED,
        TRACKING_RESUMED,
    }
)


def utc_now() -> str:
    return iso_from_epoch(datetime.now(timezone.utc).timestamp())


def iso_from_epoch(epoch: float) -> str:
    moment = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def local_now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


@dataclass
class Event:
    event_type: str
    occurred_at_utc: str
    process_name: str | None = None
    display_name: str | None = None
    session_key: str | None = None
    duration_seconds: int | None = None
    flags: dict[str, Any] = field(default_factory=dict)
    # "app" = kullanıcı uygulaması, "windows" = Windows sistem uygulaması, "" = sistem olayı
    category: str = ""
    event_id: str | None = None
    seq: int | None = None
    created_at_utc: str | None = None
    is_synced: bool = False
    attempts: int = 0
    sync_result: str | None = None

    def to_api(self) -> dict[str, Any]:
        flags = {"initial": False, "inferred": False}
        flags.update(self.flags)
        flags["initial"] = bool(flags.get("initial", False))
        flags["inferred"] = bool(flags.get("inferred", False))
        return {
            "eventId": self.event_id,
            "seq": self.seq,
            "eventType": self.event_type,
            "processName": self.process_name,
            "displayName": self.display_name,
            "sessionKey": self.session_key,
            "durationSeconds": self.duration_seconds,
            "category": self.category,
            "flags": flags,
            "occurredAtUtc": self.occurred_at_utc,
        }
