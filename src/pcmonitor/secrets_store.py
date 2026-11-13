"""DPAPI storage for the device key. The key is never logged or written as text."""

from __future__ import annotations

import sys
from pathlib import Path

_UI_FORBIDDEN = 0x01
_DESCRIPTION = "PCMonitor device key"


class SecretsError(Exception):
    """The device key could not be protected or read."""


class SecretsStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._cached: str | None = None

    def save(self, device_key: str) -> None:
        if sys.platform != "win32":
            raise SecretsError("DPAPI yalnızca Windows'ta kullanılabilir")
        if not device_key:
            raise SecretsError("Boş cihaz anahtarı saklanamaz")
        blob = _protect(device_key.encode("utf-8"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".key.tmp")
        temporary.write_bytes(blob)
        temporary.replace(self.path)
        self._cached = device_key

    def load(self) -> str | None:
        if self._cached is not None:
            return self._cached
        if not self.path.exists():
            return None
        if sys.platform != "win32":
            raise SecretsError("DPAPI yalnızca Windows'ta kullanılabilir")
        try:
            blob = self.path.read_bytes()
        except OSError as exc:
            raise SecretsError(f"Cihaz anahtarı okunamadı: {exc}") from exc
        if not blob:
            return None
        try:
            text = _unprotect(blob).decode("utf-8")
        except Exception as exc:
            raise SecretsError("Cihaz anahtarı çözülemedi") from exc
        self._cached = text
        return text

    def clear(self) -> None:
        self._cached = None
        try:
            self.path.unlink()
        except FileNotFoundError:
            return


def _protect(payload: bytes) -> bytes:
    import win32crypt

    return win32crypt.CryptProtectData(payload, _DESCRIPTION, None, None, None, _UI_FORBIDDEN)


def _unprotect(blob: bytes) -> bytes:
    import win32crypt

    _description, data = win32crypt.CryptUnprotectData(blob, None, None, None, _UI_FORBIDDEN)
    return bytes(data)
