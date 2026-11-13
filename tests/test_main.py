from __future__ import annotations

from pcmonitor.__main__ import main


def test_version(capsys) -> None:
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == "0.1.0"
