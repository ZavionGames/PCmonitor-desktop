"""Paths, config.json, and file logging."""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from logging.handlers import RotatingFileHandler
from pathlib import Path

APP_DIR_NAME = "PCMonitor"
CONFIG_FILE_NAME = "config.json"
LOG_DIR_NAME = "logs"
LOG_FILE_NAME = "agent.log"
DB_FILE_NAME = "pcmonitor.sqlite3"
SECRET_FILE_NAME = "device.key"
DATA_DIR_ENV = "PCMONITOR_DATA_DIR"
LOGGER_NAME = "pcmonitor"

LOG_MAX_BYTES = 1_048_576
LOG_BACKUP_COUNT = 5

_PLAINTEXT_SECRET_KEYS = frozenset(
    {
        "deviceKey",
        "device_key",
        "password",
        "secret",
        "token",
    }
)
_VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR"})
_KNOWN_KEYS = frozenset(
    {
        "serverUrl",
        "deviceId",
        "logLevel",
        "trayEnabled",
        "firestoreProjectId",
        "firestoreApiKey",
        "label",
    }
)


class ConfigError(Exception):
    """config.json is missing required shape or cannot be parsed."""


@dataclass
class Settings:
    server_url: str = ""
    device_id: str = ""
    log_level: str = "INFO"
    tray_enabled: bool = True
    firestore_project_id: str = ""
    firestore_api_key: str = ""
    label: str = ""
    extra: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        payload = dict(self.extra)
        payload["serverUrl"] = self.server_url
        payload["deviceId"] = self.device_id
        payload["logLevel"] = self.log_level
        payload["trayEnabled"] = self.tray_enabled
        payload["firestoreProjectId"] = self.firestore_project_id
        payload["firestoreApiKey"] = self.firestore_api_key
        payload["label"] = self.label
        return payload


def default_data_dir() -> Path:
    override = os.environ.get(DATA_DIR_ENV)
    if override:
        return Path(override)
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / APP_DIR_NAME
    return Path.home() / "AppData" / "Local" / APP_DIR_NAME


def config_path(data_dir: Path) -> Path:
    return data_dir / CONFIG_FILE_NAME


def log_dir(data_dir: Path) -> Path:
    return data_dir / LOG_DIR_NAME


def db_path(data_dir: Path) -> Path:
    return data_dir / DB_FILE_NAME


def secret_path(data_dir: Path) -> Path:
    return data_dir / SECRET_FILE_NAME


def package_default_path() -> Path:
    return Path(__file__).with_name("config.default.json")


def package_defaults() -> dict[str, object]:
    path = package_default_path()
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return raw


def load_settings(path: Path) -> Settings:
    """Load settings. Creates a default file when path does not exist."""
    defaults = package_defaults()
    if not path.exists():
        settings = _settings_from_mapping(dict(defaults))
        save_settings(path, settings)
        return settings

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config.json okunamadı: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"config.json okunamadı: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError("config.json bir JSON nesnesi olmalı")

    stripped = _without_plaintext_secrets(raw)
    changed = stripped != raw
    for key, value in defaults.items():
        if key not in stripped:
            stripped[key] = value
            changed = True
    if changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(stripped, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    return _settings_from_mapping(stripped)


def save_settings(path: Path, settings: Settings) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(settings.to_dict(), indent=2, ensure_ascii=False) + "\n"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(payload, encoding="utf-8")
    temporary.replace(path)


def configure_logging(data_dir: Path, level_name: str) -> logging.Logger:
    """Attach one rotating file handler to the pcmonitor logger."""
    target = log_dir(data_dir)
    target.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(LOGGER_NAME)
    shutdown_logging()
    logger.setLevel(_parse_log_level(level_name))
    logger.propagate = False

    formatter = logging.Formatter(
        "%(asctime)sZ %(levelname)s %(threadName)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    formatter.converter = time.gmtime

    file_handler = RotatingFileHandler(
        target / LOG_FILE_NAME,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stderr = sys.stderr
    if stderr is not None and getattr(stderr, "isatty", lambda: False)():
        console = logging.StreamHandler(stderr)
        console.setFormatter(formatter)
        logger.addHandler(console)

    return logger


def shutdown_logging() -> None:
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()


def append_log_line(data_dir: Path, level: str, message: str) -> None:
    """Write one line without keeping a handler open."""
    target = log_dir(data_dir)
    target.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = f"{stamp} {level} MainThread {LOGGER_NAME}: {message}\n"
    with (target / LOG_FILE_NAME).open("a", encoding="utf-8") as handle:
        handle.write(line)


def console_print(message: str) -> None:
    stream = sys.stdout
    if stream is None:
        return
    try:
        stream.write(message + "\n")
        stream.flush()
    except OSError:
        return


def _settings_from_mapping(raw: dict[str, object]) -> Settings:
    server_url = raw.get("serverUrl", "")
    device_id = raw.get("deviceId", "")
    log_level = raw.get("logLevel", "INFO")
    tray_enabled = raw.get("trayEnabled", True)
    project_id = raw.get("firestoreProjectId", "")
    api_key = raw.get("firestoreApiKey", "")
    label = raw.get("label", "")

    if not isinstance(server_url, str):
        raise ConfigError("serverUrl metin olmalı")
    if not isinstance(device_id, str):
        raise ConfigError("deviceId metin olmalı")
    if not isinstance(log_level, str) or log_level.upper() not in _VALID_LOG_LEVELS:
        raise ConfigError("logLevel DEBUG, INFO, WARNING veya ERROR olmalı")
    if not isinstance(tray_enabled, bool):
        raise ConfigError("trayEnabled true veya false olmalı")
    if not isinstance(project_id, str):
        raise ConfigError("firestoreProjectId metin olmalı")
    if not isinstance(api_key, str):
        raise ConfigError("firestoreApiKey metin olmalı")
    if not isinstance(label, str):
        label = ""

    extra = {key: value for key, value in raw.items() if key not in _KNOWN_KEYS}
    return Settings(
        server_url=server_url.strip(),
        device_id=device_id.strip(),
        log_level=log_level.upper(),
        tray_enabled=tray_enabled,
        firestore_project_id=project_id.strip(),
        firestore_api_key=api_key.strip(),
        label=label.strip(),
        extra=extra,
    )


def _without_plaintext_secrets(raw: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in raw.items() if key not in _PLAINTEXT_SECRET_KEYS}


def _parse_log_level(level_name: str) -> int:
    return getattr(logging, level_name.upper(), logging.INFO)
