"""Read System event-log records used to separate boot, shutdown, and restart."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from pcmonitor.models import iso_from_epoch

logger = logging.getLogger(__name__)

EVENT_SHUTDOWN_REASON = 1074
EVENT_LOG_STARTED = 6005
EVENT_LOG_STOPPED = 6006
EVENT_UNEXPECTED = 6008


@dataclass(frozen=True)
class RawRecord:
    event_id: int
    occurred_epoch: float
    inserts: tuple[str, ...]

    @property
    def occurred_at_utc(self) -> str:
        return iso_from_epoch(self.occurred_epoch)


@dataclass(frozen=True)
class BootInfo:
    boot_epoch: float | None
    source: str
    restart_hint: bool
    unexpected_epoch: float | None


def inserts_say_restart(inserts: tuple[str, ...] | list[str]) -> bool:
    text = " ".join(inserts).casefold()
    markers = ("restart", "reboot", "yeniden başlat", "yeniden baslat")
    return any(marker in text for marker in markers)


def end_session_event_type(lparam: int, restart: bool) -> str:
    unsigned = lparam & 0xFFFFFFFF
    if unsigned & 0x80000000:
        return "session_logoff"
    if restart:
        return "system_restart"
    return "system_shutdown"


def inspect_boot(records: list[RawRecord], fallback_boot_epoch: float | None) -> BootInfo:
    started = [item for item in records if item.event_id == EVENT_LOG_STARTED]
    unexpected = [item for item in records if item.event_id == EVENT_UNEXPECTED]
    reasons = [item for item in records if item.event_id == EVENT_SHUTDOWN_REASON]
    boot = max(started, key=lambda item: item.occurred_epoch) if started else None
    latest_reason = max(reasons, key=lambda item: item.occurred_epoch) if reasons else None
    latest_unexpected = (
        max(unexpected, key=lambda item: item.occurred_epoch) if unexpected else None
    )
    if boot is not None:
        source = "eventlog-6005"
        boot_epoch = boot.occurred_epoch
    else:
        source = "psutil" if fallback_boot_epoch is not None else "unknown"
        boot_epoch = fallback_boot_epoch
    return BootInfo(
        boot_epoch=boot_epoch,
        source=source,
        restart_hint=bool(latest_reason and inserts_say_restart(latest_reason.inserts)),
        unexpected_epoch=None if latest_unexpected is None else latest_unexpected.occurred_epoch,
    )


def read_recent_system_records(limit: int = 400) -> list[RawRecord]:
    if limit <= 0:
        return []
    try:
        import win32evtlog
    except ImportError:
        logger.warning("win32evtlog yok; olay günlüğü okunamadı")
        return []

    try:
        handle = win32evtlog.OpenEventLog(None, "System")
    except Exception:
        logger.warning("Sistem olay günlüğü açılamadı", exc_info=True)
        return []

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    found: list[RawRecord] = []
    try:
        while len(found) < limit:
            try:
                batch = win32evtlog.ReadEventLog(handle, flags, 0)
            except Exception:
                logger.debug("Olay günlüğü okuması bitti", exc_info=True)
                break
            if not batch:
                break
            for event in batch:
                record = _convert(event)
                if record is not None and record.event_id in {
                    EVENT_SHUTDOWN_REASON,
                    EVENT_LOG_STARTED,
                    EVENT_LOG_STOPPED,
                    EVENT_UNEXPECTED,
                }:
                    found.append(record)
                if len(found) >= limit:
                    break
    finally:
        win32evtlog.CloseEventLog(handle)
    return found


def recent_restart_hint(limit: int = 40) -> bool:
    info = inspect_boot(read_recent_system_records(limit), None)
    return info.restart_hint


def _convert(event: object) -> RawRecord | None:
    try:
        event_id = int(getattr(event, "EventID")) & 0xFFFF
        generated = getattr(event, "TimeGenerated")
        if hasattr(generated, "timestamp"):
            epoch = float(generated.timestamp())
        else:
            epoch = float(generated)
        inserts_raw = getattr(event, "StringInserts", None) or ()
        inserts = tuple(str(item) for item in inserts_raw if item is not None)
    except (TypeError, ValueError, OverflowError):
        return None
    return RawRecord(event_id=event_id, occurred_epoch=epoch, inserts=inserts)
