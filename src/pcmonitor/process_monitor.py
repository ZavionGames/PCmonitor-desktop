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

DEFAULT_BLOCKED_NAMES = frozenset(
    {
        # Windows çekirdek süreçleri
        "svchost", "svchost.exe",
        "explorer", "explorer.exe",
        "dwm", "dwm.exe",
        "csrss", "csrss.exe",
        "wininit", "wininit.exe",
        "services", "services.exe",
        "lsass", "lsass.exe",
        "winlogon", "winlogon.exe",
        "conhost", "conhost.exe",
        "werfault", "werfault.exe",
        "taskhostw", "taskhostw.exe",
        "runtimebroker", "runtimebroker.exe",
        "searchhost", "searchhost.exe",
        "system", "registry",
        "smss", "smss.exe",
        "fontdrvhost", "fontdrvhost.exe",
        "sihost", "sihost.exe",
        "ctfmon", "ctfmon.exe",
        "dllhost", "dllhost.exe",
        "applicationframehost", "applicationframehost.exe",
        "textinputhost", "textinputhost.exe",
        "shellexperiencehost", "shellexperiencehost.exe",
        "startmenuexperiencehost", "startmenuexperiencehost.exe",
        "securityhealthservice", "securityhealthservice.exe",
        "msmpeng", "msmpeng.exe",
        "nissrv", "nissrv.exe",
        "memory compression", "idle", "secure system",
        "searchindexer", "searchindexer.exe",
        "spoolsv", "spoolsv.exe",
        "wmiprvse", "wmiprvse.exe",
        "tiworker", "tiworker.exe",
        "trustedinstaller", "trustedinstaller.exe",
        "msdtc", "msdtc.exe",
        "lsaiso", "lsaiso.exe",
        # Windows Update / bakım
        "wuauclt", "wuauclt.exe",
        "musnotification", "musnotification.exe",
        "musnotificationux", "musnotificationux.exe",
        "updatenotificationmgr", "updatenotificationmgr.exe",
        "usocoreworker", "usocoreworker.exe",
        "usoclient", "usoclient.exe",
        "waasmedicagent", "waasmedicagent.exe",
        "sedsvc", "sedsvc.exe",
        # Güvenlik / AV arka plan servisleri
        "mpcmdrun", "mpcmdrun.exe",
        "securityhealthsystray", "securityhealthsystray.exe",
        "smartscreen", "smartscreen.exe",
        "wscsvc", "wscsvc.exe",
        "msseces", "msseces.exe",
        # Telemetri / diagnostics
        "compattelrunner", "compattelrunner.exe",
        "diaghost", "diaghost.exe",
        "diagtrack", "diagtrack.exe",
        "wsqmcons", "wsqmcons.exe",
        "pcasvc", "pcasvc.exe",
        "dxdiag", "dxdiag.exe",
        # Tarayıcı yardımcı süreçleri (Chrome/Edge/Firefox alt süreçleri)
        # Bunlar ana exe ile aynı isimde gelir, gruplama zaten tek oturum yapıyor
        # Ancak bu isimleri tamamen bloklamak istemiyoruz — gruplama yeterli
        # Runtime / framework altyapısı
        "taskmgr", "taskmgr.exe",
        "msiexec", "msiexec.exe",
        "regsvr32", "regsvr32.exe",
        "rundll32", "rundll32.exe",
        "wscript", "wscript.exe",
        "cscript", "cscript.exe",
        "cmd", "cmd.exe",
        "powershell", "powershell.exe",
        "pwsh", "pwsh.exe",
        # Sistem tepsisi yardımcıları
        "igfxem", "igfxem.exe",
        "igfxtray", "igfxtray.exe",
        "igfxhk", "igfxhk.exe",
        "nvdisplay.container.exe",
        "nvcontainer", "nvcontainer.exe",
        "nvspcaps64", "nvspcaps64.exe",
        "amdow", "amdow.exe",
        "radeoninstaller", "radeoninstaller.exe",
        # Ses / cihaz servisleri
        "audiodg", "audiodg.exe",
        "soundswitch", "soundswitch.exe",
        # OneDrive / bulut sync arka plan
        "onedrive", "onedrive.exe",
        "googledrivefs", "googledrivefs.exe",
        # PCMonitor'ün kendisi
        "python", "python.exe",
        "pythonw", "pythonw.exe",
        "pcmonitor", "pcmonitor.exe",
    }
)


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
            "pids": [[pid, created] for pid, created in sorted(self.pids)],
        }


class ProcessTracker:
    """Pure session state. The thread supplies already filtered samples."""

    def __init__(self, snapshot: dict[str, Any] | None = None) -> None:
        self.sessions: dict[str, TrackedSession] = {}
        self.last_scan_epoch: float | None = None
        self._reconciled = False
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
            self.sessions[str(item["identity"])] = TrackedSession(
                identity=str(item["identity"]),
                process_name=str(item.get("processName") or ""),
                display_name=str(item.get("displayName") or ""),
                session_key=str(item.get("sessionKey") or ""),
                started_epoch=started,
                announced=bool(item.get("announced", False)),
                initial=bool(item.get("initial", False)),
                pids=pids,
            )

    def export_snapshot(self) -> dict[str, Any]:
        return {
            "lastScanEpoch": self.last_scan_epoch,
            "sessions": [session.export() for session in self.sessions.values()],
        }

    def apply(self, procs: list[ProcSample], now_epoch: float) -> list[Event]:
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
        for identity, samples in grouped.items():
            if identity in self.sessions:
                session = self.sessions[identity]
                if not session.announced and _age(now_epoch, session.started_epoch) >= DEBOUNCE_SECONDS:
                    session.announced = True
                    events.append(_started(session, initial=False))
                continue
            session = _new_session(identity, samples, initial=True, announced=True)
            self.sessions[identity] = session
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
            if not session.announced and _age(now_epoch, session.started_epoch) >= DEBOUNCE_SECONDS:
                session.announced = True
                events.append(_started(session, initial=False))
        for identity, samples in grouped.items():
            if identity in self.sessions:
                continue
            session = _new_session(identity, samples, initial=False, announced=False)
            self.sessions[identity] = session
            if _age(now_epoch, session.started_epoch) >= DEBOUNCE_SECONDS:
                session.announced = True
                events.append(_started(session, initial=False))
        return events


def is_tracked(
    sample: ProcSample,
    filt: FilterConfig,
    windir: str,
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
    explicitly = _matches_any(folded, stem, exe, filt.tracked)
    blocked = folded in DEFAULT_BLOCKED_NAMES or f"{stem}.exe" in DEFAULT_BLOCKED_NAMES or stem in {
        Path(item).stem for item in DEFAULT_BLOCKED_NAMES
    }
    if blocked and not explicitly:
        return False
    if exe and _under_windir(exe, windir) and not explicitly:
        return False
    if filt.tracked and not explicitly:
        return False
    return True


def needs_exe_lookup(name: str, filt: FilterConfig) -> bool:
    if any(_is_path_token(token) for token in filt.tracked) or any(
        _is_path_token(token) for token in filt.ignored
    ):
        return True
    folded = name.casefold()
    stem = Path(name).stem.casefold()
    if _matches_any(folded, stem, "", filt.tracked):
        return True
    blocked = folded in DEFAULT_BLOCKED_NAMES or stem in {Path(item).stem for item in DEFAULT_BLOCKED_NAMES}
    return not blocked


def list_processes(filt: FilterConfig, own_pids: set[int], windir: str) -> list[ProcSample]:
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
        exe: str | None = None
        if needs_exe_lookup(str(name), filt):
            exe = _query_exe(proc, pid)
            preliminary = ProcSample(
                pid=pid,
                name=str(name),
                create_time=float(created),
                exe=exe,
                display_name=Path(exe).stem if exe else (Path(str(name)).stem or str(name)),
            )
        if is_tracked(preliminary, filt, windir, own_pids):
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
        logger.info("Yürütülebilir yol alınamadı pid=%s", pid)
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


def _get_window_exe_paths() -> frozenset[str]:
    """Görünür penceresi olan süreçlerin EXE yollarını döner.

    Aynı exe'den bir tane bile pencereye sahipse, o exe'nin tüm
    süreçleri "app" kategorisine girer (ör. Chrome renderer süreçleri).
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

        # EnumWindows
        get_window_thread_process_id = user32.GetWindowThreadProcessId
        get_window_thread_process_id.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        get_window_thread_process_id.restype = wintypes.DWORD
        is_window_visible = user32.IsWindowVisible
        is_window_visible.argtypes = [wintypes.HWND]
        is_window_visible.restype = wintypes.BOOL
        get_window_text_length = user32.GetWindowTextLengthW
        get_window_text_length.argtypes = [wintypes.HWND]
        get_window_text_length.restype = ctypes.c_int

        # OpenProcess + QueryFullProcessImageNameW
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        OpenProcess = kernel32.OpenProcess
        OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        OpenProcess.restype = wintypes.HANDLE
        QueryFullProcessImageNameW = kernel32.QueryFullProcessImageNameW
        QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        QueryFullProcessImageNameW.restype = wintypes.BOOL
        CloseHandle = kernel32.CloseHandle
        CloseHandle.argtypes = [wintypes.HANDLE]
        CloseHandle.restype = wintypes.BOOL

        window_pids: set[int] = set()

        @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        def enum_callback(hwnd: int, _lparam: int) -> bool:
            if is_window_visible(hwnd) and get_window_text_length(hwnd) > 0:
                pid = wintypes.DWORD(0)
                get_window_thread_process_id(hwnd, ctypes.byref(pid))
                if pid.value:
                    window_pids.add(pid.value)
            return True

        user32.EnumWindows(enum_callback, 0)

        # Her pencere PID'i için exe yolunu al
        for pid in window_pids:
            try:
                handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                if handle:
                    try:
                        buf = ctypes.create_unicode_buffer(1024)
                        size = wintypes.DWORD(1024)
                        if QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                            exe_paths.add(os.path.normcase(os.path.normpath(buf.value)))
                    finally:
                        CloseHandle(handle)
            except Exception:
                pass
    except Exception:
        pass

    _WINDOW_EXE_CACHE = frozenset(exe_paths)
    _WINDOW_CACHE_TIME = now
    return _WINDOW_EXE_CACHE


def _get_pids_with_windows() -> set[int]:
    """Görünür penceresi olan PID'leri döner (geriye dönuk uyumluluk için)."""
    # Basit implementasyon: pencere olan exe yollarını dönen fonksiyonu çağır
    # ama PID lazımdır, boş set dön (artık kullanılmıyor)
    return set()


def _categorize_exe(exe: str | None, pid: int = 0) -> str:
    """Kategori belirle.

    1. Aynı exe'den birinde pencere varsa → "app" (kullanıcı görüyor)
    2. C:\\Windows\\ altı (penceresiz)  → "windows"
    3. Yoksa                           → "windows"
    """
    if not exe:
        return "windows"

    normalized = os.path.normcase(os.path.normpath(exe))

    # ÖNCE pencere kontrolü — kullanıcı açtığı her şey "app"
    # (Notepad C:\Windows altında ama kullanıcı açtı → app)
    window_exes = _get_window_exe_paths()
    if normalized in window_exes:
        return "app"

    # Pencere yoksa C:\Windows altı → windows
    windir = os.path.normcase(os.path.normpath(os.environ.get("WINDIR", r"C:\Windows")))
    if normalized.startswith(windir + os.sep):
        return "windows"

    return "windows"


def _started(session: TrackedSession, *, initial: bool) -> Event:
    # İlk pid'i al (kategori için)
    first_pid = next(iter(session.pids), (0, 0))[0]
    return Event(
        event_type=PROCESS_STARTED,
        occurred_at_utc=iso_from_epoch(session.started_epoch),
        process_name=session.process_name,
        display_name=session.display_name,
        session_key=session.session_key,
        category=_categorize_exe(session.exe, first_pid),
        flags={"initial": initial, "inferred": False},
    )


def _stopped(session: TrackedSession, ended_epoch: float, *, inferred: bool) -> Event:
    duration = int(max(0, ended_epoch - session.started_epoch))
    first_pid = next(iter(session.pids), (0, 0))[0]
    return Event(
        event_type=PROCESS_STOPPED,
        occurred_at_utc=iso_from_epoch(ended_epoch),
        process_name=session.process_name,
        display_name=session.display_name,
        session_key=session.session_key,
        duration_seconds=duration,
        category=_categorize_exe(session.exe, first_pid),
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


def _under_windir(exe: str, windir: str) -> bool:
    try:
        path = Path(os.path.normcase(os.path.normpath(exe)))
        root = Path(os.path.normcase(os.path.normpath(windir)))
        path.relative_to(root)
        return True
    except ValueError:
        return False


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
        samples = list_processes(filt, {self._own_pid}, windir_path())
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
                "Olay %s %s session=%s",
                stored.event_type,
                stored.process_name,
                stored.session_key,
            )
        self._db.set_state(  # type: ignore[attr-defined]
            self._state_apps,
            self._json.dumps(self._tracker.export_snapshot(), ensure_ascii=False),
        )
