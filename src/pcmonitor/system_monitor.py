"""Hidden window for power, session, and shutdown messages."""

from __future__ import annotations

import logging
import os
import threading
import time

from pcmonitor.db import STATE_CLEAN_EXIT, STATE_SHUTDOWN_RECORDED, Database
from pcmonitor.eventlog_reader import end_session_event_type, recent_restart_hint
from pcmonitor.models import (
    SESSION_LOCK,
    SESSION_LOGOFF,
    SESSION_LOGON,
    SESSION_UNLOCK,
    SYSTEM_HIBERNATE,
    SYSTEM_RESUME,
    SYSTEM_SLEEP,
    Event,
    utc_now,
)

logger = logging.getLogger(__name__)

WM_POWERBROADCAST = 0x0218
PBT_APMSUSPEND = 0x0004
PBT_APMRESUMESUSPEND = 0x0007
PBT_APMRESUMECRITICAL = 0x0006
PBT_APMRESUMEAUTOMATIC = 0x0012
WM_WTSSESSION_CHANGE = 0x02B1
WTS_SESSION_LOGON = 0x5
WTS_SESSION_LOGOFF = 0x6
WTS_SESSION_LOCK = 0x7
WTS_SESSION_UNLOCK = 0x8

_SESSION_EVENTS = {
    WTS_SESSION_LOGON: SESSION_LOGON,
    WTS_SESSION_LOGOFF: SESSION_LOGOFF,
    WTS_SESSION_LOCK: SESSION_LOCK,
    WTS_SESSION_UNLOCK: SESSION_UNLOCK,
}


class SystemMonitor:
    def __init__(
        self,
        database: Database,
        stop_event: threading.Event,
        track_system_events: object,
    ) -> None:
        self._db = database
        self._stop = stop_event
        self._track_system_events = track_system_events
        self._hwnd: int | None = None
        self._class_atom: int | None = None
        self._wndproc: object | None = None
        self._ready = threading.Event()
        self._last_power = 0.0
        self._last_power_kind = ""
        self.system_ending = False

    def run(self) -> None:
        try:
            import win32api
            import win32con
            import win32gui
            import win32ts
        except ImportError:
            logger.warning("pywin32 yok; sistem olayları izlenmeyecek")
            self._ready.set()
            return

        if self._stop.is_set():
            self._ready.set()
            return

        class_name = f"PCMonitorHidden_{os.getpid()}"
        hinstance = win32api.GetModuleHandle(None)

        def wndproc(hwnd: int, msg: int, wparam: int, lparam: int) -> int:
            try:
                if msg == WM_POWERBROADCAST:
                    self._on_power(int(wparam))
                    return 1
                if msg == WM_WTSSESSION_CHANGE:
                    self._on_session(int(wparam))
                    return 0
                if msg == win32con.WM_QUERYENDSESSION:
                    return 1
                if msg == win32con.WM_ENDSESSION:
                    if int(wparam):
                        self._on_end_session(int(lparam))
                    return 0
            except Exception:
                logger.exception("Sistem mesajı işlenemedi")
            return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

        self._wndproc = wndproc
        window_class = win32gui.WNDCLASS()
        window_class.hInstance = hinstance
        window_class.lpszClassName = class_name
        window_class.lpfnWndProc = wndproc
        try:
            self._class_atom = win32gui.RegisterClass(window_class)
        except Exception:
            logger.exception("Pencere sınıfı kaydedilemedi")
            self._ready.set()
            return

        try:
            hwnd = win32gui.CreateWindow(
                class_name,
                "PCMonitor",
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                hinstance,
                None,
            )
        except Exception:
            logger.exception("Gizli pencere oluşturulamadı")
            self._ready.set()
            return

        self._hwnd = int(hwnd)
        try:
            notify = getattr(win32ts, "NOTIFY_FOR_THIS_SESSION", 0)
            win32ts.WTSRegisterSessionNotification(hwnd, notify)
        except Exception:
            logger.exception("Oturum bildirimleri kaydedilemedi")

        self._ready.set()
        if self._stop.is_set():
            self._destroy()
            return
        win32gui.PumpMessages()
        self._destroy()

    def request_stop(self) -> None:
        self._stop.set()
        hwnd = self._hwnd
        if not hwnd:
            return
        try:
            import win32con
            import win32gui

            win32gui.PostMessage(hwnd, win32con.WM_QUIT, 0, 0)
        except Exception:
            logger.debug("Pencere kapatma iletisi gönderilemedi", exc_info=True)

    def wait_ready(self, timeout: float) -> bool:
        return self._ready.wait(timeout)

    def _tracking(self) -> bool:
        try:
            return bool(self._track_system_events())  # type: ignore[operator]
        except Exception:
            logger.exception("Sistem olayı ayarı okunamadı")
            return True

    def _on_power(self, wparam: int) -> None:
        if not self._tracking():
            return
        now = time.monotonic()
        if wparam == PBT_APMSUSPEND:
            if self._duplicate_power("sleep", now):
                return
            # Windows sends the same suspend message for sleep and hibernate.
            self._emit(
                SYSTEM_SLEEP,
                {"initial": False, "inferred": False, "hibernate": "unknown", "bestEffort": True},
            )
            return
        if wparam in {PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND, PBT_APMRESUMECRITICAL}:
            if self._duplicate_power("resume", now):
                return
            self._emit(SYSTEM_RESUME, {"initial": False, "inferred": False, "bestEffort": True})

    def _duplicate_power(self, kind: str, now: float) -> bool:
        if kind == self._last_power_kind and now - self._last_power < 3:
            return True
        self._last_power = now
        self._last_power_kind = kind
        return False

    def _on_session(self, wparam: int) -> None:
        if not self._tracking():
            return
        event_type = _SESSION_EVENTS.get(wparam)
        if event_type is None:
            return
        self._emit(event_type, {"initial": False, "inferred": False})

    def _on_end_session(self, lparam: int) -> None:
        self.system_ending = True
        restart = False
        try:
            restart = recent_restart_hint()
        except Exception:
            logger.exception("Kapanış nedeni okunamadı")
        event_type = end_session_event_type(lparam, restart)
        if event_type == "system_shutdown" and not restart:
            # Best-effort hibernate is not distinguished here; sleep uses WM_POWERBROADCAST.
            pass
        self._record_ending(event_type)
        self._stop.set()

    def _record_ending(self, event_type: str) -> None:
        if self._db.get_state(STATE_SHUTDOWN_RECORDED) == "1":
            self._db.set_state(STATE_CLEAN_EXIT, "1")
            return
        flags = {"initial": False, "inferred": False, "bestEffort": True}
        if event_type == SYSTEM_HIBERNATE:
            flags["hibernate"] = "guess"
        self._db.add_event(
            Event(event_type=event_type, occurred_at_utc=utc_now(), flags=flags)
        )
        self._db.set_state(STATE_SHUTDOWN_RECORDED, "1")
        self._db.set_state(STATE_CLEAN_EXIT, "1")
        logger.info("Sistem kapanış olayı yazıldı: %s", event_type)

    def _emit(self, event_type: str, flags: dict[str, object]) -> None:
        self._db.add_event(
            Event(event_type=event_type, occurred_at_utc=utc_now(), flags=flags)
        )
        logger.info("Sistem olayı %s", event_type)

    def _destroy(self) -> None:
        hwnd = self._hwnd
        self._hwnd = None
        if not hwnd:
            return
        try:
            import win32gui
            import win32ts

            try:
                win32ts.WTSUnRegisterSessionNotification(hwnd)
            except Exception:
                logger.debug("Oturum bildirimi kaldırılamadı", exc_info=True)
            win32gui.DestroyWindow(hwnd)
        except Exception:
            logger.debug("Gizli pencere kapatılamadı", exc_info=True)
        if self._class_atom is not None:
            try:
                import win32api
                import win32gui

                win32gui.UnregisterClass(self._class_atom, win32api.GetModuleHandle(None))
            except Exception:
                logger.debug("Pencere sınıfı silinemedi", exc_info=True)
            self._class_atom = None
