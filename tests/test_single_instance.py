from __future__ import annotations

import uuid

import pytest

from pcmonitor.single_instance import SingleInstance

pytestmark = pytest.mark.skipif(
    __import__("sys").platform != "win32",
    reason="named mutex is Windows-only",
)


def test_second_acquire_fails_until_release() -> None:
    name = rf"Local\PCMonitorTest{uuid.uuid4().hex}"
    first = SingleInstance(name)
    second = SingleInstance(name)
    assert first.acquire() is True
    try:
        assert second.acquire() is False
        assert second.acquired is False
    finally:
        first.release()
    assert second.acquire() is True
    second.release()


def test_release_is_idempotent() -> None:
    name = rf"Local\PCMonitorTest{uuid.uuid4().hex}"
    instance = SingleInstance(name)
    assert instance.acquire() is True
    instance.release()
    instance.release()
    assert instance.acquired is False
