"""Minimal tray icon. The agent does not show a desktop event window."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger(__name__)


def run_tray(
    *,
    log_directory: Path,
    is_paused: Callable[[], bool],
    on_pause: Callable[[], None],
    on_resume: Callable[[], None],
    on_status: Callable[[], str],
    on_exit: Callable[[], None],
    on_ready: Callable[[object], None],
) -> None:
    try:
        import pystray
        from PIL import Image, ImageDraw
    except ImportError:
        logger.error("pystray veya Pillow yok; tepsi simgesi başlatılamadı")
        return

    image = Image.new("RGB", (64, 64), (32, 36, 42))
    draw = ImageDraw.Draw(image)
    draw.ellipse((6, 6, 58, 58), fill=(47, 111, 214))
    draw.rectangle((28, 16, 36, 46), fill=(255, 255, 255))
    draw.rectangle((22, 28, 42, 36), fill=(255, 255, 255))

    def _pause(_icon: object, _item: object) -> None:
        on_pause()

    def _resume(_icon: object, _item: object) -> None:
        on_resume()

    def _open_logs(_icon: object, _item: object) -> None:
        try:
            os.startfile(log_directory)  # type: ignore[attr-defined]
        except OSError:
            logger.exception("Log klasörü açılamadı")

    def _status(icon: object, _item: object) -> None:
        text = on_status()
        logger.info(text)
        notify = getattr(icon, "notify", None)
        if notify is None:
            return
        try:
            notify(text, "PCMonitor")
        except Exception:
            logger.debug("Tepsi bildirimi gösterilemedi", exc_info=True)

    def _exit(icon: object, _item: object) -> None:
        on_exit()
        stop = getattr(icon, "stop", None)
        if stop is not None:
            stop()

    menu = pystray.Menu(
        pystray.MenuItem("Takibi duraklat", _pause, enabled=lambda _item: not is_paused()),
        pystray.MenuItem("Takibi devam ettir", _resume, enabled=lambda _item: is_paused()),
        pystray.MenuItem("Log klasörünü aç", _open_logs),
        pystray.MenuItem("Durumu göster", _status),
        pystray.MenuItem("Çıkış", _exit),
    )
    icon = pystray.Icon("PCMonitor", image, "PCMonitor", menu)

    def _setup(ready_icon: object) -> None:
        visible = getattr(ready_icon, "visible", None)
        if visible is not None:
            ready_icon.visible = True  # type: ignore[attr-defined]
        on_ready(ready_icon)

    icon.run(_setup)
