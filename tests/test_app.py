from __future__ import annotations

import json
import threading
import uuid

import pytest

from pcmonitor.app import AgentApp
from pcmonitor.config import shutdown_logging

pytestmark = pytest.mark.skipif(
    __import__("sys").platform != "win32",
    reason="agent lifecycle uses a Windows mutex",
)


@pytest.fixture(autouse=True)
def _close_log_handlers():
    yield
    shutdown_logging()


def test_run_stops_and_writes_log(tmp_path) -> None:
    app = AgentApp(data_dir=tmp_path, mutex_name=_mutex_name())
    exit_code: dict[str, int] = {}

    def _run() -> None:
        exit_code["code"] = app.run()

    thread = threading.Thread(target=_run)
    thread.start()
    assert app.ready.wait(5)
    app.request_stop()
    thread.join(5)

    assert not thread.is_alive()
    assert exit_code["code"] == 0
    log_text = (tmp_path / "logs" / "agent.log").read_text(encoding="utf-8")
    assert "Agent başladı" in log_text
    assert "Agent durdu" in log_text
    config = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert config["deviceId"] == ""
    assert "deviceKey" not in config


def test_second_instance_exits(tmp_path) -> None:
    name = _mutex_name()
    first = AgentApp(data_dir=tmp_path, mutex_name=name)
    thread = threading.Thread(target=first.run)
    thread.start()
    assert first.ready.wait(5)
    try:
        second = AgentApp(data_dir=tmp_path, mutex_name=name)
        assert second.run() == 1
        log_text = (tmp_path / "logs" / "agent.log").read_text(encoding="utf-8")
        assert "Başka bir PCMonitor agent" in log_text
    finally:
        first.request_stop()
        thread.join(5)


def test_corrupt_config_returns_2(tmp_path) -> None:
    (tmp_path / "config.json").write_text("{", encoding="utf-8")
    app = AgentApp(data_dir=tmp_path, mutex_name=_mutex_name())
    assert app.run() == 2
    log_text = (tmp_path / "logs" / "agent.log").read_text(encoding="utf-8")
    assert "config.json" in log_text


def _mutex_name() -> str:
    return rf"Local\PCMonitorTest{uuid.uuid4().hex}"
