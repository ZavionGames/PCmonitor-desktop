"""HKCU Run entry. No administrator right."""

from __future__ import annotations

import sys
from pathlib import Path

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "PCMonitor"


class AutostartError(Exception):
    """The Run key could not be changed."""


def pythonw_executable(executable: str | None = None) -> str:
    if getattr(sys, "frozen", False):
        return executable or sys.executable
    current = Path(executable or sys.executable)
    if current.name.lower() == "python.exe":
        sibling = current.with_name("pythonw.exe")
        if sibling.exists():
            return str(sibling)
    return str(current)


def autostart_command(executable: str | None = None) -> str:
    launcher = pythonw_executable(executable)
    if getattr(sys, "frozen", False):
        return f'"{launcher}"'
    return f'"{launcher}" -m pcmonitor'


def install_autostart(command: str | None = None) -> str:
    value = command or autostart_command()
    _write_run_value(value)
    return value


def remove_autostart() -> bool:
    if sys.platform != "win32":
        raise AutostartError("Otomatik başlatma yalnızca Windows'ta değiştirilebilir")
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, VALUE_NAME)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise AutostartError(f"Otomatik başlatma kaldırılamadı: {exc}") from exc
    return True


def query_autostart() -> str | None:
    if sys.platform != "win32":
        return None
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as key:
            value, _kind = winreg.QueryValueEx(key, VALUE_NAME)
    except FileNotFoundError:
        return None
    except OSError:
        return None
    return str(value)


def _write_run_value(value: str) -> None:
    if sys.platform != "win32":
        raise AutostartError("Otomatik başlatma yalnızca Windows'ta değiştirilebilir")
    import winreg

    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, value)
    except OSError as exc:
        raise AutostartError(f"Otomatik başlatma yazılamadı: {exc}") from exc
