from __future__ import annotations

import json

import pytest

from pcmonitor.config import ConfigError, Settings, load_settings, save_settings


def test_missing_file_creates_defaults(tmp_path) -> None:
    path = tmp_path / "config.json"
    settings = load_settings(path)
    assert settings.server_url == ""
    assert settings.device_id == ""
    assert settings.log_level == "INFO"
    assert settings.tray_enabled is True
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert "deviceKey" not in stored
    assert stored["serverUrl"] == ""


def test_round_trip_preserves_unknown_keys(tmp_path) -> None:
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "serverUrl": "https://example.test",
                "deviceId": "dev-1",
                "logLevel": "debug",
                "trayEnabled": False,
                "configVersion": 3,
            }
        ),
        encoding="utf-8",
    )
    settings = load_settings(path)
    assert settings.server_url == "https://example.test"
    assert settings.device_id == "dev-1"
    assert settings.log_level == "DEBUG"
    assert settings.tray_enabled is False
    assert settings.extra == {"configVersion": 3}

    settings.device_id = "dev-2"
    save_settings(path, settings)
    again = json.loads(path.read_text(encoding="utf-8"))
    assert again["deviceId"] == "dev-2"
    assert again["configVersion"] == 3
    assert not (tmp_path / "config.json.tmp").exists()


def test_plaintext_secret_keys_are_removed(tmp_path) -> None:
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps({"serverUrl": "https://example.test", "deviceKey": "super-secret"}),
        encoding="utf-8",
    )
    settings = load_settings(path)
    assert settings.server_url == "https://example.test"
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert "deviceKey" not in stored
    assert "super-secret" not in path.read_text(encoding="utf-8")


def test_invalid_json_raises(tmp_path) -> None:
    path = tmp_path / "config.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_settings(path)


def test_invalid_log_level_raises(tmp_path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"logLevel": "verbose"}), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_settings(path)


def test_settings_to_dict_known_keys_win() -> None:
    settings = Settings(server_url="https://a.test", extra={"serverUrl": "nope", "note": 1})
    payload = settings.to_dict()
    assert payload["serverUrl"] == "https://a.test"
    assert payload["note"] == 1
