"""Named mutex so only one agent runs in the current Windows session."""

from __future__ import annotations

import sys

MUTEX_NAME = r"Local\PCMonitorAgent"

_ERROR_ALREADY_EXISTS = 183


class SingleInstanceError(Exception):
    """The mutex could not be created."""


class SingleInstance:
    """Keeps a named mutex handle open for the life of this process.

    The mutex is not owned. Closing the handle (or process exit) releases the
    name. A second CreateMutex in the same session sees ERROR_ALREADY_EXISTS.
    ``Local\\`` avoids the admin right required for ``Global\\``.
    """

    def __init__(self, name: str = MUTEX_NAME) -> None:
        if sys.platform != "win32":
            raise SingleInstanceError("PCMonitor agent yalnızca Windows'ta çalışır")
        self._name = name
        self._handle: object | None = None

    @property
    def acquired(self) -> bool:
        return self._handle is not None

    def acquire(self) -> bool:
        if self._handle is not None:
            return True

        import win32api
        import win32event

        win32api.SetLastError(0)
        handle = win32event.CreateMutex(None, False, self._name)
        already_exists = win32api.GetLastError() == _ERROR_ALREADY_EXISTS
        if already_exists:
            win32api.CloseHandle(handle)
            return False
        self._handle = handle
        return True

    def release(self) -> None:
        if self._handle is None:
            return
        import win32api

        win32api.CloseHandle(self._handle)
        self._handle = None
