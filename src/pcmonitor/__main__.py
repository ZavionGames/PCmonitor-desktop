"""Command line entry: ``python -m pcmonitor`` or ``pythonw -m pcmonitor``."""

from __future__ import annotations

import argparse
import logging
import sys

from pcmonitor import __version__
from pcmonitor.app import AgentApp, save_device_id
from pcmonitor.autostart import install_autostart, remove_autostart
from pcmonitor.config import (
    config_path,
    configure_logging,
    console_print,
    db_path,
    default_data_dir,
    load_settings,
    save_settings,
    secret_path,
    shutdown_logging,
)
from pcmonitor.db import Database
from pcmonitor.firestore_test_sink import MachineIdError, announce_startup, collect_machine_facts
from pcmonitor.secrets_store import SecretsStore
from pcmonitor.sync_client import SyncError, SyncService, make_http_client

logger = logging.getLogger("pcmonitor.main")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pcmonitor",
        description="PCMonitor Windows agent",
    )
    parser.add_argument("--version", action="store_true", help="Sürümü yaz ve çık")
    parser.add_argument(
        "--test",
        action="store_true",
        help="MachineGuid'i oku, Firestore'a giriş kaydı yaz, sonucu göster ve çık",
    )
    parser.add_argument("--pair", metavar="KOD", help="Tek kullanımlık eşleştirme kodu")
    parser.add_argument("--install-autostart", action="store_true", help="Oturum açılınca başlat")
    parser.add_argument("--remove-autostart", action="store_true", help="Otomatik başlatmayı kaldır")
    parser.add_argument(
        "--set-label",
        metavar="ETİKET",
        help='Makine etiketini config.json\'a kaydet ve çık (ör. "PC 1")',
    )
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    if args.version:
        print(__version__)
        return 0

    if sys.platform != "win32":
        print("PCMonitor agent yalnızca Windows'ta çalışır", file=sys.stderr)
        return 1

    if args.set_label is not None:
        return run_set_label(args.set_label)

    if args.test:
        return run_test_mode()

    if args.pair:
        return run_pair(args.pair)

    if args.install_autostart:
        command = install_autostart()
        console_print(f"Otomatik başlatma yazıldı: {command}")
        return 0

    if args.remove_autostart:
        removed = remove_autostart()
        console_print(
            "Otomatik başlatma kaldırıldı" if removed else "Kayıtlı otomatik başlatma yoktu"
        )
        return 0

    return AgentApp().run()


def run_set_label(label: str) -> int:
    """Write the machine label to config.json and exit."""
    label = label.strip()
    data_dir = default_data_dir()
    try:
        settings = load_settings(config_path(data_dir))
    except Exception as exc:
        console_print(f"Yapılandırma okunamadı: {exc}")
        return 2

    settings.label = label
    save_settings(config_path(data_dir), settings)

    effective = label if label else settings.computer_name if hasattr(settings, "computer_name") else "(bilgisayar adı)"
    console_print(f"Etiket kaydedildi: '{label}' (etkin etiket: '{effective}')")
    return 0


def run_test_mode() -> int:
    """Read MachineGuid, write a Firestore login record, print result and exit.

    Does NOT start the background service.  Exit code 0 = success.
    """
    data_dir = default_data_dir()
    try:
        settings = load_settings(config_path(data_dir))
    except Exception as exc:
        console_print(f"Yapılandırma okunamadı: {exc}")
        return 2

    configure_logging(data_dir, settings.log_level)
    database = Database(db_path(data_dir))
    try:
        # Collect and show machine info before attempting the write.
        try:
            facts = collect_machine_facts(settings)
        except MachineIdError as exc:
            console_print(f"HATA: {exc}")
            return 1

        console_print("--- PCMonitor Test Modu ---")
        console_print(f"Agent sürümü : {facts.agent_version}")
        console_print(f"MachineGuid  : {facts.machine_guid}")
        console_print(f"Kullanıcı    : {facts.username}")
        console_print(f"Bilgisayar   : {facts.computer_name}")
        console_print(f"Etiket       : {facts.effective_label}")
        console_print(f"OS           : {facts.os_version}")
        console_print(f"Zaman (UTC)  : {facts.started_at_utc}")
        console_print(f"Zaman (yerel): {facts.started_at_local}")
        console_print("")

        line = announce_startup(database, settings, facts=facts)
        console_print(f"\nSonuç: {line}")
        return 0 if "firestore=başarılı" in line else 1
    finally:
        database.close()
        shutdown_logging()


def run_pair(code: str) -> int:
    data_dir = default_data_dir()
    try:
        settings = load_settings(config_path(data_dir))
    except Exception as exc:
        console_print(f"Yapılandırma okunamadı: {exc}")
        return 2

    configure_logging(data_dir, settings.log_level)
    database = Database(db_path(data_dir))
    http = make_http_client()
    try:
        service = SyncService(
            settings,
            database,
            SecretsStore(secret_path(data_dir)),
            http,
            status_provider=lambda: False,
            on_remote_config=lambda _remote: None,
        )
        device_id = service.pair(code.strip())
        save_device_id(data_dir, settings, device_id)
        console_print(f"Eşleştirildi deviceId={device_id}")
        logger.info("Eşleştirildi deviceId=%s", device_id)
        return 0
    except SyncError as exc:
        console_print(str(exc))
        logger.error("%s", exc)
        return 1
    finally:
        http.close()
        database.close()
        shutdown_logging()


if __name__ == "__main__":
    raise SystemExit(main())
