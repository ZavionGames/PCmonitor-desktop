"""Starts and stops the agent threads."""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from pathlib import Path

from pcmonitor import __version__
from pcmonitor.config import (
    ConfigError,
    Settings,
    append_log_line,
    config_path,
    configure_logging,
    console_print,
    db_path,
    default_data_dir,
    load_settings,
    log_dir,
    save_settings,
    secret_path,
    shutdown_logging,
)
from pcmonitor.db import (
    STATE_AUTH_BLOCKED,
    STATE_CLEAN_EXIT,
    STATE_LAST_ALIVE,
    STATE_LAST_BOOT,
    STATE_PAUSED,
    STATE_SHUTDOWN_RECORDED,
    Database,
)
from pcmonitor.eventlog_reader import inspect_boot, read_recent_system_records
from pcmonitor.firestore_test_sink import announce_startup
from pcmonitor.models import (
    AGENT_STARTED,
    AGENT_STOPPED,
    SYSTEM_STARTED,
    SYSTEM_UNEXPECTED_SHUTDOWN,
    TRACKING_PAUSED,
    TRACKING_RESUMED,
    Event,
    iso_from_epoch,
    utc_now,
)
from pcmonitor.process_monitor import FilterConfig, ProcessMonitor
from pcmonitor.secrets_store import SecretsStore
from pcmonitor.single_instance import MUTEX_NAME, SingleInstance, SingleInstanceError
from pcmonitor.sync_client import (
    RemoteConfig,
    SyncService,
    backoff_delay,
    make_http_client,
)
from pcmonitor.system_monitor import SystemMonitor

logger = logging.getLogger("pcmonitor.app")

_USER_STOP_CONTROLS = frozenset({0, 1, 2})
_SYSTEM_STOP_CONTROLS = frozenset({5, 6})


class RuntimeState:
    def __init__(self, remote: RemoteConfig, paused: bool) -> None:
        self._lock = threading.Lock()
        self.remote = remote
        self.paused = paused

    def filter_config(self) -> FilterConfig:
        with self._lock:
            return FilterConfig(
                tracked=self.remote.tracked_apps,
                ignored=self.remote.ignored_apps,
            )

    def set_remote(self, remote: RemoteConfig) -> None:
        with self._lock:
            self.remote = remote

    def track_system(self) -> bool:
        with self._lock:
            return self.remote.track_system_events


class AgentApp:
    """One agent process until request_stop, then a clean release of the mutex."""

    def __init__(
        self,
        data_dir: Path | None = None,
        mutex_name: str = MUTEX_NAME,
        start_workers: bool = True,
        announce_firestore: bool = True,
    ) -> None:
        self.data_dir = data_dir if data_dir is not None else default_data_dir()
        self._mutex_name = mutex_name
        self._start_workers = start_workers
        self._announce_firestore = announce_firestore
        self.stop_event = threading.Event()
        self.ready = threading.Event()
        self._lock = threading.Lock()
        self._instance: SingleInstance | None = None
        self._console_handler: object | None = None
        self._console_handler_running = False
        self._cleaned_up = False
        self._logging_active = False
        self._stopped = threading.Event()
        self.system_ending = False
        self._settings: Settings | None = None
        self._db: Database | None = None
        self._secrets: SecretsStore | None = None
        self._http: object | None = None
        self._sync: SyncService | None = None
        self._state: RuntimeState | None = None
        self._threads: list[threading.Thread] = []
        self._system: SystemMonitor | None = None
        self._icon: object | None = None
        self._firestore_failures = 0
        self._firestore_next = 0.0
        self._agent_stop_written = False

    def request_stop(self) -> None:
        self.stop_event.set()
        if self._system is not None:
            self._system.request_stop()

    def run(self) -> int:
        exit_code = 1
        try:
            exit_code = self._run_until_stopped()
        except KeyboardInterrupt:
            self.request_stop()
            exit_code = 0
        except ConfigError as exc:
            self._report_config_error(exc)
            exit_code = 2
        except SingleInstanceError as exc:
            self._report_fatal(str(exc))
            exit_code = 1
        finally:
            self._shutdown()
        return exit_code

    def pause_tracking(self) -> None:
        self._set_paused(True)

    def resume_tracking(self) -> None:
        self._set_paused(False)

    def status_text(self) -> str:
        if self._db is None:
            return "Agent henüz hazır değil"
        pending = self._db.pending_count()
        last_sync = "yok"
        if self._sync is not None and self._sync.last_sync_utc:
            last_sync = self._sync.last_sync_utc
        paused = "duraklatıldı" if self._state and self._state.paused else "izleniyor"
        blocked = ""
        if self._sync is not None and self._sync.auth_blocked:
            blocked = " anahtar reddedildi"
        return f"Bekleyen olay: {pending}. Son gönderim: {last_sync}. Takip: {paused}.{blocked}"

    def _run_until_stopped(self) -> int:
        settings = load_settings(config_path(self.data_dir))
        self._settings = settings
        self._instance = SingleInstance(self._mutex_name)
        if not self._instance.acquire():
            append_log_line(
                self.data_dir,
                "WARNING",
                "Başka bir PCMonitor agent örneği çalışıyor; bu süreç kapanıyor",
            )
            return 1

        configure_logging(self.data_dir, settings.log_level)
        self._logging_active = True
        logger.info("Agent başladı version=%s dataDir=%s", __version__, self.data_dir)
        self._db = Database(db_path(self.data_dir))
        self._secrets = SecretsStore(secret_path(self.data_dir))
        self._record_boot()
        remote = RemoteConfig()
        raw_remote = self._db.get_state("remoteConfig")
        if raw_remote:
            try:
                loaded = json.loads(raw_remote)
            except json.JSONDecodeError:
                loaded = None
            if isinstance(loaded, dict):
                remote = RemoteConfig.from_mapping(loaded)
        paused = self._db.get_state(STATE_PAUSED) == "1"
        self._state = RuntimeState(remote, paused)
        if self._announce_firestore:
            announce_startup(self._db, settings)
        if self._start_workers:
            self._start_threads()
        self._install_console_handler()
        self.ready.set()
        while not self.stop_event.is_set():
            self.stop_event.wait(0.5)
        logger.info("Durdurma istendi")
        return 0

    def _record_boot(self) -> None:
        assert self._db is not None
        previous_clean = self._db.get_state(STATE_CLEAN_EXIT)
        last_alive = self._db.get_state(STATE_LAST_ALIVE)
        if previous_clean != "1" and last_alive:
            self._db.add_event(
                Event(
                    event_type=SYSTEM_UNEXPECTED_SHUTDOWN,
                    occurred_at_utc=last_alive,
                    flags={"initial": False, "inferred": True},
                )
            )
            logger.info("Beklenmedik kapanış lastAlive=%s", last_alive)
        self._db.set_state(STATE_CLEAN_EXIT, "0")
        self._db.set_state(STATE_SHUTDOWN_RECORDED, "0")
        self._db.set_state(STATE_LAST_ALIVE, utc_now())

        fallback = _boot_time_fallback()
        info = inspect_boot(read_recent_system_records(), fallback)
        if info.boot_epoch is not None:
            marker = iso_from_epoch(info.boot_epoch)
            if self._db.get_state(STATE_LAST_BOOT) != marker:
                self._db.add_event(
                    Event(
                        event_type=SYSTEM_STARTED,
                        occurred_at_utc=marker,
                        flags={
                            "initial": False,
                            "inferred": False,
                            "bootTimeSource": info.source,
                            "fastStartup": "untested",
                        },
                    )
                )
                self._db.set_state(STATE_LAST_BOOT, marker)
                logger.info("Sistem açılışı %s kaynak=%s", marker, info.source)
        self._db.add_event(
            Event(
                event_type=AGENT_STARTED,
                occurred_at_utc=utc_now(),
                flags={"initial": False, "inferred": False},
            )
        )

    def _start_threads(self) -> None:
        assert self._db is not None
        assert self._settings is not None
        assert self._secrets is not None
        assert self._state is not None
        self._http = make_http_client()
        self._sync = SyncService(
            self._settings,
            self._db,
            self._secrets,
            self._http,  # type: ignore[arg-type]
            status_provider=lambda: self._state.paused if self._state else False,
            on_remote_config=self._state.set_remote,
            on_auth_blocked=lambda: self._notify(
                "Cihaz anahtarı reddedildi. Olaylar saklanıyor. --pair ile yeniden eşleştirin."
            ),
        )
        self._sync.schedule_heartbeat(time.monotonic() + self._sync.remote.heartbeat_interval_seconds)
        self._system = SystemMonitor(
            self._db,
            self.stop_event,
            self._state.track_system,
        )
        process = ProcessMonitor(
            self._db,
            self.stop_event,
            self._state.filter_config,
            lambda: self._state.paused if self._state else False,
        )
        self._threads = [
            threading.Thread(target=self._guard, args=("süreç", process.run), name="process-monitor", daemon=False),
            threading.Thread(target=self._guard, args=("sistem", self._system.run), name="system-monitor", daemon=False),
            threading.Thread(target=self._guard, args=("senkron", self._sync_loop), name="sync", daemon=False),
        ]
        if self._settings.tray_enabled:
            self._threads.append(
                threading.Thread(target=self._guard, args=("tepsi", self._run_tray), name="tray", daemon=False)
            )
        else:
            logger.warning("Tepsi kapalı. Agent log dosyasında ve web durumunda görünür.")
        for thread in self._threads:
            thread.start()

    def _sync_loop(self) -> None:
        assert self._sync is not None
        assert self._db is not None
        assert self._settings is not None
        next_purge = time.monotonic() + 60
        # Başlangıçta hemen bir sync yap
        self._flush_firestore_events_now()
        while not self.stop_event.wait(5):
            now = time.monotonic()
            if self._sync.due_events(now) and self._db.pending_count():
                try:
                    self._sync.sync_pending()
                except Exception:
                    logger.exception("Olay gönderimi")
            if self._sync.due_heartbeat(now):
                sent = False
                try:
                    sent = self._sync.heartbeat()
                except Exception:
                    logger.exception("Heartbeat")
                if sent:
                    self._sync.schedule_heartbeat(time.monotonic())
            self._flush_firestore_later()
            self._flush_firestore_events_later()
            if now >= next_purge:
                try:
                    removed = self._db.purge_synced()
                    if removed:
                        logger.info("Eski senkron olay silindi: %s", removed)
                    warning = self._db.enforce_cap()
                    if warning:
                        self._notify(warning)
                except Exception:
                    logger.exception("Kuyruk bakımı")
                next_purge = time.monotonic() + 3600

    def _flush_firestore_later(self) -> None:
        assert self._db is not None
        assert self._settings is not None
        if self._http is None or time.monotonic() < self._firestore_next:
            return
        if not self._db.pending_firestore():
            return
        from pcmonitor.firestore_test_sink import FirestoreRest, flush_outbox

        rest = FirestoreRest(
            self._settings.firestore_project_id,
            self._settings.firestore_api_key,
            self._http,  # type: ignore[arg-type]
        )
        result = flush_outbox(self._db, rest)
        if result.startswith("başarılı"):
            self._firestore_failures = 0
            self._firestore_next = time.monotonic() + 30
            logger.info("Firestore kuyruğu: %s", result)
            return
        self._firestore_failures += 1
        delay = backoff_delay(self._firestore_failures)
        self._firestore_next = time.monotonic() + delay
        logger.warning("Firestore yeniden denenecek %.0f sn: %s", delay, result)

    def _flush_firestore_events_now(self) -> None:
        """Başlangıçta hemen bekleyen olayları Firestore'a gönder."""
        if self._http is None or self._settings is None or self._db is None:
            return
        self._do_flush_firestore_events()

    def _flush_firestore_events_later(self) -> None:
        """Her döngüde bekleyen olayları Firestore'a gönder (5 dk'da bir)."""
        if self._http is None or self._settings is None or self._db is None:
            return
        now = time.monotonic()
        if now < getattr(self, "_firestore_events_next", 0.0):
            return
        self._do_flush_firestore_events()

    def _do_flush_firestore_events(self) -> None:
        """SQLite'taki senkronize edilmemiş olayları Firestore'a yaz."""
        assert self._db is not None
        assert self._settings is not None
        assert self._http is not None

        # machineGuid'i settings'ten al
        from pcmonitor.firestore_test_sink import (
            FirestoreRest,
            MachineIdError,
            flush_events_direct,
            read_machine_guid,
            write_state_to_firestore,
        )
        from pcmonitor import __version__

        try:
            machine_guid = read_machine_guid()
        except MachineIdError:
            return

        rest = FirestoreRest(
            self._settings.firestore_project_id,
            self._settings.firestore_api_key,
            self._http,  # type: ignore[arg-type]
        )

        # Bekleyen olayları çek (en fazla 50)
        pending = self._db.pending_events(50)
        if pending:
            written = flush_events_direct(pending, machine_guid, rest)
            if written > 0:
                # Başarıyla yazılanları senkronize olarak işaretle
                for event in pending[:written]:
                    if event.event_id:
                        self._db.mark_synced([event.event_id], "firestore_direct")
                logger.info("Firestore direkt olay yazıldı: %s/%s", written, len(pending))

        # state/current güncelle
        try:
            write_state_to_firestore(
                rest,
                machine_guid,
                agent_version=__version__,
                status="paused" if (self._state and self._state.paused) else "running",
                pending_count=self._db.pending_count(),
            )
        except Exception:
            logger.debug("Firestore state güncellenemedi", exc_info=True)

        # Sonraki çalışma: 5 dakika sonra
        self._firestore_events_next = time.monotonic() + 300

    def _run_tray(self) -> None:
        from pcmonitor.tray import run_tray

        run_tray(
            log_directory=log_dir(self.data_dir),
            is_paused=lambda: bool(self._state and self._state.paused),
            on_pause=self.pause_tracking,
            on_resume=self.resume_tracking,
            on_status=self.status_text,
            on_exit=self.request_stop,
            on_ready=self._set_icon,
        )

    def _set_icon(self, icon: object) -> None:
        self._icon = icon

    def _set_paused(self, paused: bool) -> None:
        if self._state is None or self._db is None:
            return
        if self._state.paused == paused:
            return
        self._state.paused = paused
        self._db.set_state(STATE_PAUSED, "1" if paused else "0")
        event_type = TRACKING_PAUSED if paused else TRACKING_RESUMED
        self._db.add_event(
            Event(
                event_type=event_type,
                occurred_at_utc=utc_now(),
                flags={"initial": False, "inferred": False},
            )
        )
        logger.info("Takip %s", "duraklatıldı" if paused else "devam ediyor")

    def _guard(self, name: str, target: object) -> None:
        try:
            target()  # type: ignore[operator]
        except Exception:
            logger.exception("%s iş parçacığı durdu", name)

    def _install_console_handler(self) -> None:
        if sys.platform != "win32":
            return
        try:
            import win32api
        except ImportError:
            logger.warning("pywin32 yok; konsol kapanış sinyali yakalanmayacak")
            return

        def _handler(ctrl_type: int) -> bool:
            if ctrl_type in _SYSTEM_STOP_CONTROLS:
                self.system_ending = True
                self._console_handler_running = True
                self.request_stop()
                self._stopped.wait(4)
                return True
            if ctrl_type in _USER_STOP_CONTROLS:
                self._console_handler_running = True
                self.request_stop()
                self._stopped.wait(4)
                return True
            return False

        try:
            win32api.SetConsoleCtrlHandler(_handler, True)
        except win32api.error:
            logger.info("Konsol yok; kontrol işleyicisi atlandı")
            return
        self._console_handler = _handler

    def _remove_console_handler(self) -> None:
        handler = self._console_handler
        self._console_handler = None
        if handler is None or sys.platform != "win32":
            return
        try:
            import win32api

            win32api.SetConsoleCtrlHandler(handler, False)
        except Exception:
            logger.debug("Konsol kontrol işleyicisi kaldırılamadı", exc_info=True)

    def _shutdown(self) -> None:
        with self._lock:
            if self._cleaned_up:
                self._stopped.set()
                return
            self._cleaned_up = True
        self.request_stop()
        if self._system is not None and self._system.system_ending:
            self.system_ending = True
        for thread in self._threads:
            thread.join(timeout=5)
            if thread.is_alive():
                logger.warning("İş parçacığı kapanmadı: %s", thread.name)
        self._write_agent_stopped()
        self._final_flush()
        if self._http is not None:
            close = getattr(self._http, "close", None)
            if close is not None:
                close()
            self._http = None
        if self._db is not None:
            self._db.close()
            self._db = None
        if not self._console_handler_running:
            self._remove_console_handler()
        if self._logging_active:
            logger.info("Agent durdu")
            shutdown_logging()
            self._logging_active = False
        if self._instance is not None:
            self._instance.release()
            self._instance = None
        self._stopped.set()

    def _write_agent_stopped(self) -> None:
        if self._db is None or self._agent_stop_written:
            return
        if self.system_ending or self._db.get_state(STATE_SHUTDOWN_RECORDED) == "1":
            self._db.set_state(STATE_CLEAN_EXIT, "1")
            return
        self._db.add_event(
            Event(
                event_type=AGENT_STOPPED,
                occurred_at_utc=utc_now(),
                flags={"initial": False, "inferred": False},
            )
        )
        self._db.set_state(STATE_CLEAN_EXIT, "1")
        self._agent_stop_written = True
        logger.info("agent_stopped yazıldı")

    def _final_flush(self) -> None:
        if self._db is None or self._settings is None or self._http is None:
            return
        try:
            # 1. Web API senkron
            if not self.system_ending and self._sync is not None:
                self._sync.sync_pending()

            from pcmonitor.firestore_test_sink import (
                FirestoreRest, flush_outbox, flush_events_direct,
                read_machine_guid, write_state_to_firestore, MachineIdError,
            )
            from pcmonitor import __version__

            rest = FirestoreRest(
                self._settings.firestore_project_id,
                self._settings.firestore_api_key,
                self._http,  # type: ignore[arg-type]
            )

            # 2. Firestore outbox (login/machine kayıtları)
            flush_outbox(self._db, rest)

            # 3. Kalan olayları Firestore'a yaz
            pending = self._db.pending_events(100)
            if pending:
                written = flush_events_direct(pending, _get_machine_guid(), rest)
                for event in pending[:written]:
                    if event.event_id:
                        self._db.mark_synced([event.event_id], "firestore_shutdown")

            # 4. Kapanış durumunu Firestore'a bildir (offline)
            try:
                machine_guid = read_machine_guid()
                write_state_to_firestore(
                    rest,
                    machine_guid,
                    agent_version=__version__,
                    status="offline",
                    pending_count=0,
                )
                logger.info("Firestore: kapanış durumu yazıldı (offline)")
            except MachineIdError:
                pass
        except Exception:
            logger.exception("Kapanış gönderimi")

    def _notify(self, message: str) -> None:
        logger.warning(message)
        icon = self._icon
        notify = getattr(icon, "notify", None) if icon is not None else None
        if notify is None:
            return
        try:
            notify(message, "PCMonitor")
        except Exception:
            logger.debug("Bildirim gösterilemedi", exc_info=True)

    def _report_config_error(self, exc: ConfigError) -> None:
        message = str(exc)
        try:
            append_log_line(self.data_dir, "ERROR", message)
        except OSError:
            pass
        _write_stderr(message)

    def _report_fatal(self, message: str) -> None:
        try:
            append_log_line(self.data_dir, "ERROR", message)
        except OSError:
            pass
        _write_stderr(message)


def save_device_id(data_dir: Path, settings: Settings, device_id: str) -> None:
    settings.device_id = device_id
    save_settings(config_path(data_dir), settings)


def _get_machine_guid() -> str:
    """MachineGuid'i okur; hata olursa boş string döner."""
    try:
        from pcmonitor.firestore_test_sink import read_machine_guid
        return read_machine_guid()
    except Exception:
        return ""


def _boot_time_fallback() -> float | None:
    try:
        import psutil
    except ImportError:
        return None
    try:
        return float(psutil.boot_time())
    except Exception:
        logger.debug("psutil boot_time okunamadı", exc_info=True)
        return None


def _write_stderr(message: str) -> None:
    stderr = sys.stderr
    if stderr is None:
        return
    try:
        stderr.write(message + "\n")
    except OSError:
        return
