"""psutil diff, grouping, filters, debounce, and restart reconciliation."""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pcmonitor.models import (
    PROCESS_STARTED,
    PROCESS_STOPPED,
    Event,
    iso_from_epoch,
)

logger = logging.getLogger(__name__)

DEBOUNCE_SECONDS = 3.0
POLL_SECONDS = 2.0


@dataclass(frozen=True)
class FilterConfig:
    tracked: tuple[str, ...] = ()
    ignored: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProcSample:
    pid: int
    name: str
    create_time: float
    exe: str | None
    display_name: str


@dataclass
class TrackedSession:
    identity: str
    process_name: str
    display_name: str
    session_key: str
    started_epoch: float
    announced: bool
    initial: bool
    exe: str | None = None
    category: str = ""
    pids: set[tuple[int, float]] = field(default_factory=set)

    def export(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "processName": self.process_name,
            "displayName": self.display_name,
            "sessionKey": self.session_key,
            "startedEpoch": self.started_epoch,
            "announced": self.announced,
            "initial": self.initial,
            "exe": self.exe,
            "category": self.category,
            "pids": [[pid, created] for pid, created in sorted(self.pids)],
        }


class ProcessTracker:
    """Pure session state. The thread supplies already filtered samples."""

    def __init__(self, snapshot: dict[str, Any] | None = None) -> None:
        self.sessions: dict[str, TrackedSession] = {}
        self.last_scan_epoch: float | None = None
        self._reconciled = False
        self.category_upgrades: list[str] = []
        if not snapshot:
            return
        last_scan = snapshot.get("lastScanEpoch")
        if isinstance(last_scan, (int, float)):
            self.last_scan_epoch = float(last_scan)
        for item in snapshot.get("sessions", []):
            if not isinstance(item, dict) or "identity" not in item:
                continue
            pids = {
                (int(pair[0]), float(pair[1]))
                for pair in item.get("pids", [])
                if isinstance(pair, (list, tuple)) and len(pair) == 2
            }
            started = float(item.get("startedEpoch", 0))
            identity = str(item["identity"])
            raw_exe = item.get("exe")
            if isinstance(raw_exe, str) and raw_exe:
                exe = raw_exe
            elif identity.startswith("name:"):
                exe = None
            else:
                exe = identity
            raw_category = item.get("category")
            category = raw_category if raw_category in ("app", "windows") else ""
            # Eski anlık görüntüde kategori yoktu; bir kez doğru sınıfla yeniden duyur.
            announced = bool(item.get("announced", False)) and bool(category)
            self.sessions[identity] = TrackedSession(
                identity=identity,
                process_name=str(item.get("processName") or ""),
                display_name=str(item.get("displayName") or ""),
                session_key=str(item.get("sessionKey") or ""),
                started_epoch=started,
                announced=announced,
                initial=bool(item.get("initial", False)),
                exe=exe,
                category=category,
                pids=pids,
            )

    def export_snapshot(self) -> dict[str, Any]:
        return {
            "lastScanEpoch": self.last_scan_epoch,
            "sessions": [session.export() for session in self.sessions.values()],
        }

    def apply(self, procs: list[ProcSample], now_epoch: float) -> list[Event]:
        self.category_upgrades = []
        grouped = _group(procs)
        if not self._reconciled:
            events = self._reconcile(grouped, now_epoch)
            self._reconciled = True
        else:
            events = self._diff(grouped, now_epoch)
        self.last_scan_epoch = now_epoch
        return events

    def _reconcile(
        self,
        grouped: dict[str, list[ProcSample]],
        now_epoch: float,
    ) -> list[Event]:
        events: list[Event] = []
        previous_scan = self.last_scan_epoch if self.last_scan_epoch is not None else now_epoch
        for identity in list(self.sessions):
            session = self.sessions[identity]
            if identity not in grouped:
                if session.announced:
                    events.append(_stopped(session, previous_scan, inferred=True))
                del self.sessions[identity]
                continue
            session.pids = _pid_set(grouped[identity])
            session.display_name = grouped[identity][0].display_name or session.display_name
            self._refresh_category(session, grouped[identity])
        for identity, samples in grouped.items():
            if identity in self.sessions:
                session = self.sessions[identity]
                if not session.announced and _age(now_epoch, session.started_epoch) >= DEBOUNCE_SECONDS:
                    self._refresh_category(session, samples)
                    session.announced = True
                    events.append(_started(session, initial=False))
                continue
            session = _new_session(identity, samples, initial=True, announced=True)
            self.sessions[identity] = session
            self._refresh_category(session, samples)
            events.append(_started(session, initial=True))
        return events

    def _diff(
        self,
        grouped: dict[str, list[ProcSample]],
        now_epoch: float,
    ) -> list[Event]:
        events: list[Event] = []
        for identity in list(self.sessions):
            session = self.sessions[identity]
            if identity not in grouped:
                if session.announced:
                    events.append(_stopped(session, now_epoch, inferred=False))
                del self.sessions[identity]
                continue
            session.pids = _pid_set(grouped[identity])
            session.display_name = grouped[identity][0].display_name or session.display_name
            self._refresh_category(session, grouped[identity])
            if not session.announced and _age(now_epoch, session.started_epoch) >= DEBOUNCE_SECONDS:
                session.announced = True
                events.append(_started(session, initial=False))
        for identity, samples in grouped.items():
            if identity in self.sessions:
                continue
            session = _new_session(identity, samples, initial=False, announced=False)
            self.sessions[identity] = session
            self._refresh_category(session, samples)
            if _age(now_epoch, session.started_epoch) >= DEBOUNCE_SECONDS:
                session.announced = True
                events.append(_started(session, initial=False))
        return events

    def _refresh_category(self, session: TrackedSession, samples: list[ProcSample]) -> None:
        sample_exe = samples[0].exe if samples else None
        if sample_exe:
            session.exe = sample_exe
        already = session.announced
        if _promote_category(session) and already and session.session_key:
            self.category_upgrades.append(session.session_key)


def is_tracked(
    sample: ProcSample,
    filt: FilterConfig,
    own_pids: set[int],
) -> bool:
    if sample.pid in own_pids or sample.pid <= 4:
        return False
    name = sample.name.strip()
    if not name:
        return False
    folded = name.casefold()
    stem = Path(name).stem.casefold()
    exe = sample.exe or ""
    if _matches_any(folded, stem, exe, filt.ignored):
        return False
    if filt.tracked and not _matches_any(folded, stem, exe, filt.tracked):
        return False
    return True


def list_processes(filt: FilterConfig, own_pids: set[int]) -> list[ProcSample]:
    import psutil

    samples: list[ProcSample] = []
    for proc in psutil.process_iter(["pid", "name", "create_time"]):
        info = proc.info
        pid = info.get("pid")
        name = info.get("name") or ""
        created = info.get("create_time")
        if not isinstance(pid, int) or not isinstance(created, (int, float)):
            continue
        preliminary = ProcSample(
            pid=pid,
            name=str(name),
            create_time=float(created),
            exe=None,
            display_name=Path(str(name)).stem or str(name),
        )
        if pid in own_pids or pid <= 4:
            continue
        exe = _query_exe(proc, pid)
        preliminary = ProcSample(
            pid=pid,
            name=str(name),
            create_time=float(created),
            exe=exe,
            display_name=Path(exe).stem if exe else (Path(str(name)).stem or str(name)),
        )
        if is_tracked(preliminary, filt, own_pids):
            samples.append(preliminary)
    return samples


def windir_path() -> str:
    return os.environ.get("WINDIR", r"C:\Windows")


def display_name_for(exe: str | None, fallback: str, cache: dict[str, str]) -> str:
    if not exe:
        return Path(fallback).stem or fallback
    cached = cache.get(exe)
    if cached:
        return cached
    description = _file_description(exe)
    chosen = description or Path(exe).stem or fallback
    cache[exe] = chosen
    return chosen


def _file_description(path: str) -> str | None:
    try:
        import win32api

        language = win32api.GetFileVersionInfo(path, r"\VarFileInfo\Translation")
        if not language:
            return None
        lang, codepage = language[0]
        key = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\FileDescription"
        value = win32api.GetFileVersionInfo(path, key)
    except Exception:
        return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _query_exe(proc: object, pid: int) -> str | None:
    try:
        exe = proc.exe()  # type: ignore[attr-defined]
    except Exception:
        exe = None
    if exe:
        return str(exe)
    fallback = _query_full_image_name(pid)
    if fallback is None:
        logger.debug("Yürütülebilir yol alınamadı pid=%s", pid)
    return fallback


def _query_full_image_name(pid: int) -> str | None:
    import ctypes
    from ctypes import wintypes

    process_query_limited = 0x1000
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    query_name = kernel32.QueryFullProcessImageNameW
    query_name.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    query_name.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    handle = open_process(process_query_limited, False, pid)
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not query_name(handle, 0, buffer, ctypes.byref(size)):
            return None
        value = buffer.value.strip()
        return value or None
    finally:
        close_handle(handle)


def _group(procs: list[ProcSample]) -> dict[str, list[ProcSample]]:
    grouped: dict[str, list[ProcSample]] = {}
    for sample in procs:
        identity = _identity(sample)
        grouped.setdefault(identity, []).append(sample)
    return grouped


def _identity(sample: ProcSample) -> str:
    if sample.exe:
        return os.path.normcase(os.path.normpath(sample.exe))
    return f"name:{sample.name.casefold()}"


def _process_name(sample: ProcSample) -> str:
    if sample.exe:
        return Path(sample.exe).name
    return sample.name


def _new_session(
    identity: str,
    samples: list[ProcSample],
    *,
    initial: bool,
    announced: bool,
) -> TrackedSession:
    started = min(sample.create_time for sample in samples)
    process_name = _process_name(samples[0])
    display = samples[0].display_name or Path(process_name).stem
    exe = samples[0].exe
    return TrackedSession(
        identity=identity,
        process_name=process_name,
        display_name=display,
        session_key=f"{process_name}|{iso_from_epoch(started)}",
        started_epoch=started,
        announced=announced,
        initial=initial,
        exe=exe,
        pids=_pid_set(samples),
    )


def _pid_set(samples: list[ProcSample]) -> set[tuple[int, float]]:
    return {(sample.pid, sample.create_time) for sample in samples}


def _get_service_exe_paths() -> frozenset[str]:
    """Windows servis listesinden exe yollarını topla (bir kere çalıştır, önbelle)."""
    try:
        import win32service
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
        try:
            services = win32service.EnumServicesStatusEx(scm)
            paths: set[str] = set()
            for svc in services:
                try:
                    handle = win32service.OpenService(scm, svc["ServiceName"],
                                                      win32service.SERVICE_QUERY_CONFIG)
                    try:
                        cfg = win32service.QueryServiceConfig(handle)
                        raw = cfg[3]  # BinaryPathName
                        # "C:\path\to\svc.exe" -args şeklinde gelebilir
                        path = raw.strip().strip('"').split('"')[0].split(' -')[0].strip()
                        if path:
                            paths.add(os.path.normcase(os.path.normpath(path)))
                    finally:
                        win32service.CloseServiceHandle(handle)
                except Exception:
                    pass
        finally:
            win32service.CloseServiceHandle(scm)
        return frozenset(paths)
    except Exception:
        return frozenset()


_SERVICE_PATHS: frozenset[str] | None = None
_WINDOW_EXE_CACHE: frozenset[str] = frozenset()
_WINDOW_CACHE_TIME: float = 0.0
_WINDOW_CACHE_TTL: float = 5.0  # saniye


def _is_service_exe(exe: str) -> bool:
    """Verilen exe bir Windows servisi olarak kayıtlı mı?"""
    global _SERVICE_PATHS
    if _SERVICE_PATHS is None:
        _SERVICE_PATHS = _get_service_exe_paths()
    normalized = os.path.normcase(os.path.normpath(exe))
    return normalized in _SERVICE_PATHS



# Görev çubuğunda görünen pencere: araç penceresi değil, sahibi yok
# ya da WS_EX_APPWINDOW ile özellikle uygulama penceresi olarak işaretli.
_WS_EX_TOOLWINDOW = 0x00000080
_WS_EX_APPWINDOW = 0x00040000
_GWL_EXSTYLE = -20
_GW_OWNER = 4
_DWMWA_CLOAKED = 14


def _normalize_exe(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def _image_path(kernel32: Any, pid: int) -> str | None:
    """Süreç kimliğinden exe yolu. Erişilemezse None."""
    import ctypes
    from ctypes import wintypes

    handle = kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return None
    try:
        size = wintypes.DWORD(1024)
        buf = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return None
        value = buf.value.strip()
        return _normalize_exe(value) if value else None
    finally:
        kernel32.CloseHandle(handle)


def _window_aumid(hwnd: int) -> str | None:
    """UWP çerçeve penceresinin paket kimliği."""
    try:
        from win32com.propsys import propsys, pscon

        value = propsys.SHGetPropertyStoreForWindow(hwnd).GetValue(pscon.PKEY_AppUserModel_ID).GetValue()
    except Exception:
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return None


def _exes_for_aumids(aumids: set[str]) -> dict[str, str]:
    """Paket kimliğini, o paketi çalıştıran exe yoluna çevir."""
    if not aumids:
        return {}
    try:
        import ctypes
        from ctypes import wintypes

        import psutil

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        open_process = kernel32.OpenProcess
        open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        open_process.restype = wintypes.HANDLE
        get_aumid = kernel32.GetApplicationUserModelId
        get_aumid.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.UINT), wintypes.LPWSTR]
        get_aumid.restype = wintypes.LONG
        query_name = kernel32.QueryFullProcessImageNameW
        query_name.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
        ]
        query_name.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL

        found: dict[str, str] = {}
        remaining = set(aumids)
        for proc in psutil.process_iter(["pid"]):
            if not remaining:
                break
            pid = proc.info.get("pid")
            if not isinstance(pid, int) or pid <= 4:
                continue
            handle = open_process(0x1000, False, pid)
            if not handle:
                continue
            try:
                length = wintypes.UINT(512)
                buf = ctypes.create_unicode_buffer(length.value)
                if get_aumid(handle, ctypes.byref(length), buf) != 0:
                    continue
                if buf.value not in remaining:
                    continue
                size = wintypes.DWORD(1024)
                image = ctypes.create_unicode_buffer(size.value)
                if query_name(handle, 0, image, ctypes.byref(size)) and image.value:
                    found[buf.value] = _normalize_exe(image.value)
                    remaining.discard(buf.value)
            finally:
                close_handle(handle)
        return found
    except Exception:
        logger.debug("UWP uygulama yolu alınamadı", exc_info=True)
        return {}


def _get_window_exe_paths() -> frozenset[str]:
    """Kullanıcının açtığı pencerenin exe yolları.

    Görev çubuğuna düşen pencere uygulamadır: görünür, başlıklı,
    kabuk tarafından gizlenmemiş, araç penceresi değil.
    UWP çerçevesi ApplicationFrameHost yerine asıl uygulamaya yazılır.
    """
    global _WINDOW_EXE_CACHE, _WINDOW_CACHE_TIME
    now = time.time()
    if now - _WINDOW_CACHE_TIME < _WINDOW_CACHE_TTL:
        return _WINDOW_EXE_CACHE

    exe_paths: set[str] = set()
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)

        get_pid = user32.GetWindowThreadProcessId
        get_pid.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        get_pid.restype = wintypes.DWORD
        is_visible = user32.IsWindowVisible
        is_visible.argtypes = [wintypes.HWND]
        is_visible.restype = wintypes.BOOL
        text_length = user32.GetWindowTextLengthW
        text_length.argtypes = [wintypes.HWND]
        text_length.restype = ctypes.c_int
        get_window = user32.GetWindow
        get_window.argtypes = [wintypes.HWND, ctypes.c_uint]
        get_window.restype = wintypes.HWND
        get_class_name = user32.GetClassNameW
        get_class_name.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        get_class_name.restype = ctypes.c_int
        get_exstyle = getattr(user32, "GetWindowLongPtrW", user32.GetWindowLongW)
        get_exstyle.argtypes = [wintypes.HWND, ctypes.c_int]
        get_exstyle.restype = ctypes.c_ssize_t
        dwm_get = dwmapi.DwmGetWindowAttribute
        dwm_get.argtypes = [wintypes.HWND, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint]
        dwm_get.restype = ctypes.c_long
        open_process = kernel32.OpenProcess
        open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        open_process.restype = wintypes.HANDLE
        query_name = kernel32.QueryFullProcessImageNameW
        query_name.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
        ]
        query_name.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL

        direct_pids: set[int] = set()
        frames: list[tuple[int, str | None]] = []

        def is_user_window(hwnd: int) -> bool:
            if not is_visible(hwnd) or text_length(hwnd) <= 0:
                return False
            cloaked = ctypes.c_int(0)
            if dwm_get(hwnd, _DWMWA_CLOAKED, ctypes.byref(cloaked), ctypes.sizeof(cloaked)) == 0:
                if cloaked.value:
                    return False
            exstyle = int(get_exstyle(hwnd, _GWL_EXSTYLE)) & 0xFFFFFFFF
            owner = get_window(hwnd, _GW_OWNER)
            tool_window = bool(exstyle & _WS_EX_TOOLWINDOW)
            app_window = bool(exstyle & _WS_EX_APPWINDOW)
            return app_window or (not owner and not tool_window)

        @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        def enum_callback(hwnd: int, _lparam: int) -> bool:
            if not is_user_window(hwnd):
                return True
            pid = wintypes.DWORD(0)
            get_pid(hwnd, ctypes.byref(pid))
            class_name = ctypes.create_unicode_buffer(256)
            get_class_name(hwnd, class_name, 256)
            if class_name.value == "ApplicationFrameWindow" and pid.value:
                frames.append((pid.value, _window_aumid(int(hwnd))))
            elif pid.value:
                direct_pids.add(pid.value)
            return True

        user32.EnumWindows(enum_callback, 0)

        for pid in direct_pids:
            try:
                exe = _image_path(kernel32, pid)
            except Exception:
                exe = None
            if exe:
                exe_paths.add(exe)

        hosted = _exes_for_aumids({aumid for _, aumid in frames if aumid})
        for pid, aumid in frames:
            exe = hosted.get(aumid or "")
            if exe:
                exe_paths.add(exe)
                continue
            try:
                fallback = _image_path(kernel32, pid)
            except Exception:
                fallback = None
            if fallback:
                exe_paths.add(fallback)
    except Exception:
        logger.debug("Kullanıcı penceresi taranamadı", exc_info=True)

    _WINDOW_EXE_CACHE = frozenset(exe_paths)
    _WINDOW_CACHE_TIME = now
    return _WINDOW_EXE_CACHE


def _categorize_exe(exe: str | None, pid: int = 0) -> str:
    """Kullanıcı penceresi olan exe uygulama, geri kalan her şey Windows."""
    del pid
    if not exe:
        return "windows"
    if _normalize_exe(exe) in _get_window_exe_paths():
        return "app"
    return "windows"


def _promote_category(session: TrackedSession) -> bool:
    """Kategoriyi pencere durumuna göre yaz.

    Uygulama bir kez pencere açtıysa oturum uygulama kalır.
    Pencere sonradan açılırsa arka plan oturumu uygulamaya yükselir.
    """
    if session.category == "app":
        return False
    if _categorize_exe(session.exe) == "app":
        session.category = "app"
        return True
    if session.category not in ("app", "windows"):
        session.category = "windows"
    return False


def _session_category(session: TrackedSession) -> str:
    if session.category in ("app", "windows"):
        return session.category
    return "windows"


def _started(session: TrackedSession, *, initial: bool) -> Event:
    return Event(
        event_type=PROCESS_STARTED,
        occurred_at_utc=iso_from_epoch(session.started_epoch),
        process_name=session.process_name,
        display_name=session.display_name,
        session_key=session.session_key,
        category=_session_category(session),
        flags={"initial": initial, "inferred": False},
    )


def _stopped(session: TrackedSession, ended_epoch: float, *, inferred: bool) -> Event:
    duration = int(max(0, ended_epoch - session.started_epoch))
    return Event(
        event_type=PROCESS_STOPPED,
        occurred_at_utc=iso_from_epoch(ended_epoch),
        process_name=session.process_name,
        display_name=session.display_name,
        session_key=session.session_key,
        duration_seconds=duration,
        category=_session_category(session),
        flags={"initial": False, "inferred": inferred},
    )


def _age(now_epoch: float, started_epoch: float) -> float:
    return max(0.0, now_epoch - started_epoch)


def _matches_any(folded_name: str, stem: str, exe: str, tokens: tuple[str, ...]) -> bool:
    for token in tokens:
        if _match_token(folded_name, stem, exe, token):
            return True
    return False


def _match_token(folded_name: str, stem: str, exe: str, token: str) -> bool:
    cleaned = token.strip()
    if not cleaned:
        return False
    if _is_path_token(cleaned):
        if not exe:
            return False
        left = os.path.normcase(os.path.normpath(exe))
        right = os.path.normcase(os.path.normpath(cleaned))
        return left == right or left.endswith(right)
    folded = cleaned.casefold()
    token_stem = Path(cleaned).stem.casefold()
    return folded in {folded_name, stem, f"{stem}.exe"} or token_stem == stem


def _is_path_token(token: str) -> bool:
    return "\\" in token or "/" in token or ":" in token


class ProcessMonitor:
    """Polls every 2 seconds and writes session events through the database."""

    def __init__(
        self,
        database: object,
        stop_event: object,
        filter_provider: object,
        paused_provider: object,
        own_pid: int | None = None,
    ) -> None:
        import json

        from pcmonitor.db import STATE_LAST_ALIVE, STATE_RUNNING_APPS

        self._db = database
        self._stop = stop_event
        self._filter_provider = filter_provider
        self._paused_provider = paused_provider
        self._own_pid = os.getpid() if own_pid is None else own_pid
        self._names: dict[str, str] = {}
        raw = database.get_state(STATE_RUNNING_APPS)  # type: ignore[attr-defined]
        snapshot = None
        if raw:
            try:
                loaded = json.loads(raw)
            except json.JSONDecodeError:
                loaded = None
            if isinstance(loaded, dict):
                snapshot = loaded
        self._tracker = ProcessTracker(snapshot)
        self._state_apps = STATE_RUNNING_APPS
        self._state_alive = STATE_LAST_ALIVE
        self._json = json

    def run(self) -> None:
        last_alive = 0.0
        while not self._stop.is_set():  # type: ignore[attr-defined]
            now = time.time()
            try:
                if now - last_alive >= 30:
                    self._db.set_state(self._state_alive, iso_from_epoch(now))  # type: ignore[attr-defined]
                    last_alive = now
                if not self._paused_provider():  # type: ignore[operator]
                    self._scan(now)
            except Exception:
                logger.exception("Süreç taraması başarısız")
            self._stop.wait(POLL_SECONDS)  # type: ignore[attr-defined]

    def _scan(self, now: float) -> None:
        filt = self._filter_provider()  # type: ignore[operator]
        samples = list_processes(filt, {self._own_pid})
        named: list[ProcSample] = []
        for sample in samples:
            display = display_name_for(sample.exe, sample.display_name, self._names)
            named.append(
                ProcSample(
                    pid=sample.pid,
                    name=sample.name,
                    create_time=sample.create_time,
                    exe=sample.exe,
                    display_name=display,
                )
            )
        events = self._tracker.apply(named, now)
        for event in events:
            stored = self._db.add_event(event)  # type: ignore[attr-defined]
            logger.info(
                "Olay %s %s session=%s category=%s",
                stored.event_type,
                stored.process_name,
                stored.session_key,
                stored.category,
            )
        for session_key in self._tracker.category_upgrades:
            self._db.set_unsynced_category(session_key, "app")  # type: ignore[attr-defined]
        self._db.set_state(  # type: ignore[attr-defined]
            self._state_apps,
            self._json.dumps(self._tracker.export_snapshot(), ensure_ascii=False),
        )
