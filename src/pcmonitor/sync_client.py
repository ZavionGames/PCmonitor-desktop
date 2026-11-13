"""Web API client: pairing, batches, heartbeat, config, and backoff."""

from __future__ import annotations

import json
import logging
import random
import socket
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from pcmonitor import __version__
from pcmonitor.config import Settings
from pcmonitor.db import (
    STATE_AUTH_BLOCKED,
    STATE_CONFIG_VERSION,
    STATE_DEVICE_ID,
    STATE_LAST_SYNC,
    STATE_REMOTE_CONFIG,
    Database,
)
from pcmonitor.models import Event, utc_now
from pcmonitor.secrets_store import SecretsStore

logger = logging.getLogger(__name__)

BATCH_LIMIT = 50
BATCH_BYTES = 256 * 1024
REQUEST_TIMEOUT = 10.0
MIN_EVENT_GAP_SECONDS = 30.0
DEFAULT_HEARTBEAT_SECONDS = 300
MIN_HEARTBEAT_SECONDS = 60
MAX_BACKOFF_SECONDS = 15 * 60


@dataclass
class RemoteConfig:
    config_version: int = 0
    tracked_apps: tuple[str, ...] = ()
    ignored_apps: tuple[str, ...] = ()
    track_system_events: bool = True
    heartbeat_interval_seconds: int = DEFAULT_HEARTBEAT_SECONDS

    def to_json(self) -> str:
        return json.dumps(
            {
                "configVersion": self.config_version,
                "trackedApps": list(self.tracked_apps),
                "ignoredApps": list(self.ignored_apps),
                "trackSystemEvents": self.track_system_events,
                "heartbeatIntervalSeconds": self.heartbeat_interval_seconds,
            },
            ensure_ascii=False,
        )

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> RemoteConfig:
        tracked = raw.get("trackedApps") or []
        ignored = raw.get("ignoredApps") or []
        interval = raw.get("heartbeatIntervalSeconds", DEFAULT_HEARTBEAT_SECONDS)
        try:
            interval_value = int(interval)
        except (TypeError, ValueError):
            interval_value = DEFAULT_HEARTBEAT_SECONDS
        interval_value = max(MIN_HEARTBEAT_SECONDS, interval_value)
        version = raw.get("configVersion", 0)
        try:
            version_value = int(version)
        except (TypeError, ValueError):
            version_value = 0
        return cls(
            config_version=version_value,
            tracked_apps=tuple(str(item) for item in tracked if isinstance(item, str)),
            ignored_apps=tuple(str(item) for item in ignored if isinstance(item, str)),
            track_system_events=bool(raw.get("trackSystemEvents", True)),
            heartbeat_interval_seconds=interval_value,
        )


def server_url_allowed(server_url: str) -> bool:
    parsed = urlparse(server_url.strip())
    if parsed.scheme == "https" and parsed.hostname:
        return True
    host = (parsed.hostname or "").casefold()
    return parsed.scheme == "http" and host in {"127.0.0.1", "localhost"}


def backoff_delay(attempt: int, rng: random.Random | None = None) -> float:
    """Seconds to wait after a failure. attempt 1 waits about 1s, then doubles, cap 15 min."""
    step = max(1, attempt)
    base = min(MAX_BACKOFF_SECONDS, float(2 ** (step - 1)))
    source = rng or random
    return min(MAX_BACKOFF_SECONDS, base + source.random())


def select_batch(events: list[Event], limit: int = BATCH_LIMIT, max_bytes: int = BATCH_BYTES) -> list[Event]:
    chosen: list[Event] = []
    size = 2
    for event in events:
        if len(chosen) >= limit:
            break
        encoded = json.dumps(event.to_api(), ensure_ascii=False).encode("utf-8")
        extra = len(encoded) + 1
        if chosen and size + extra > max_bytes:
            break
        chosen.append(event)
        size += extra
    return chosen


class SyncService:
    def __init__(
        self,
        settings: Settings,
        database: Database,
        secrets: SecretsStore,
        client: httpx.Client,
        status_provider: object,
        on_remote_config: object,
        on_auth_blocked: object | None = None,
    ) -> None:
        self._settings = settings
        self._db = database
        self._secrets = secrets
        self._client = client
        self._status_provider = status_provider
        self._on_remote_config = on_remote_config
        self._on_auth_blocked = on_auth_blocked
        self._rng = random.Random()
        self._next_web_at = 0.0
        self._failures = 0
        self._next_heartbeat_at = 0.0
        self._auth_blocked = self._db.get_state(STATE_AUTH_BLOCKED) == "1"
        self._remote = self._load_remote()

    @property
    def remote(self) -> RemoteConfig:
        return self._remote

    @property
    def auth_blocked(self) -> bool:
        return self._auth_blocked

    @property
    def last_sync_utc(self) -> str | None:
        return self._db.get_state(STATE_LAST_SYNC)

    def pair(self, code: str) -> str:
        if not server_url_allowed(self._settings.server_url):
            raise SyncError("serverUrl https olmalı (testte yalnızca localhost http)")
        response = self._client.post(
            self._url("/api/pair"),
            json={
                "code": code,
                "deviceName": socket.gethostname(),
                "agentVersion": __version__,
            },
        )
        if response.status_code >= 400:
            raise SyncError(f"Eşleştirme başarısız: HTTP {response.status_code}")
        body = response.json()
        device_id = str(body.get("deviceId") or "")
        device_key = str(body.get("deviceKey") or "")
        if not device_id or not device_key:
            raise SyncError("Eşleştirme yanıtında deviceId veya deviceKey yok")
        self._secrets.save(device_key)
        self._settings.device_id = device_id
        self._db.set_state(STATE_DEVICE_ID, device_id)
        self._db.set_state(STATE_AUTH_BLOCKED, "0")
        self._auth_blocked = False
        self._failures = 0
        self._next_web_at = 0
        return device_id

    def sync_pending(self) -> int:
        if not self._web_ready():
            return 0
        pending = self._db.pending_events(BATCH_LIMIT * 2)
        batch = select_batch(pending)
        if not batch:
            return 0
        payload = {
            "deviceId": self._settings.device_id,
            "events": [event.to_api() for event in batch],
        }
        try:
            response = self._client.post(
                self._url("/api/events"),
                json=payload,
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            self._fail_web(batch, f"ağ: {exc.__class__.__name__}")
            return 0
        if response.status_code in {401, 403} and self._is_auth_failure(response):
            self._block_auth()
            return 0
        if response.status_code == 429 or response.status_code >= 500 or response.status_code == 403:
            self._fail_web(batch, f"HTTP {response.status_code}")
            return 0
        if response.status_code >= 400:
            self._fail_web(batch, f"HTTP {response.status_code}")
            return 0
        self._succeed_web()
        self._apply_results(batch, response)
        self._db.set_state(STATE_LAST_SYNC, utc_now())
        return len(batch)

    def heartbeat(self) -> bool:
        if not self._web_ready():
            return True
        status = "paused" if self._status_provider() else "running"  # type: ignore[operator]
        body = {
            "deviceId": self._settings.device_id,
            "status": status,
            "agentVersion": __version__,
            "pendingCount": self._db.pending_count(),
            "configVersion": self._remote.config_version,
        }
        try:
            response = self._client.post(
                self._url("/api/heartbeat"),
                json=body,
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            self._fail_web([], f"heartbeat ağ: {exc.__class__.__name__}")
            return False
        if response.status_code in {401, 403} and self._is_auth_failure(response):
            self._block_auth()
            return False
        if response.status_code == 429 or response.status_code >= 500 or response.status_code == 403:
            self._fail_web([], f"heartbeat HTTP {response.status_code}")
            return False
        if response.status_code >= 400:
            self._fail_web([], f"heartbeat HTTP {response.status_code}")
            return False
        self._succeed_web()
        try:
            payload = response.json()
        except json.JSONDecodeError:
            return True
        version = payload.get("configVersion")
        try:
            version_value = int(version)
        except (TypeError, ValueError):
            return True
        if version_value != self._remote.config_version:
            self.refresh_config()
        return True

    def refresh_config(self) -> None:
        if not self._web_ready():
            return
        try:
            response = self._client.get(self._url("/api/config"), headers=self._headers())
        except httpx.HTTPError:
            logger.warning("Yapılandırma alınamadı", exc_info=True)
            return
        if response.status_code >= 400:
            logger.warning("Yapılandırma HTTP %s", response.status_code)
            return
        try:
            remote = RemoteConfig.from_mapping(response.json())
        except json.JSONDecodeError:
            logger.warning("Yapılandırma JSON değil")
            return
        self._remote = remote
        self._db.set_state(STATE_REMOTE_CONFIG, remote.to_json())
        self._db.set_state(STATE_CONFIG_VERSION, str(remote.config_version))
        self._on_remote_config(remote)  # type: ignore[operator]
        logger.info("Uzak yapılandırma sürümü %s", remote.config_version)

    def due_events(self, now: float) -> bool:
        return now >= self._next_web_at

    def due_heartbeat(self, now: float) -> bool:
        return now >= self._next_heartbeat_at

    def schedule_heartbeat(self, now: float) -> None:
        self._next_heartbeat_at = now + self._remote.heartbeat_interval_seconds

    def _web_ready(self) -> bool:
        if self._auth_blocked:
            return False
        if not self._settings.device_id or not server_url_allowed(self._settings.server_url):
            return False
        return self._secrets.load() is not None

    def _headers(self) -> dict[str, str]:
        key = self._secrets.load() or ""
        return {
            "Authorization": f"Bearer {key}",
            "X-Device-Id": self._settings.device_id,
        }

    def _url(self, path: str) -> str:
        return self._settings.server_url.rstrip("/") + path

    def _apply_results(self, batch: list[Event], response: httpx.Response) -> None:
        try:
            body = response.json()
        except json.JSONDecodeError:
            logger.warning("Olay yanıtı JSON değil; kuyruk bekletildi")
            self._db.mark_attempt_failed([event.event_id or "" for event in batch])
            return
        results = body.get("results")
        if not isinstance(results, list):
            logger.warning("Olay yanıtında results yok")
            return
        by_id = {event.event_id: event for event in batch}
        seen: set[str] = set()
        for item in results:
            if not isinstance(item, dict):
                continue
            event_id = str(item.get("eventId") or "")
            status = str(item.get("status") or "")
            seen.add(event_id)
            if event_id not in by_id:
                logger.warning("Yanıtta bilinmeyen eventId")
                continue
            if status in {"accepted", "duplicate"}:
                self._db.mark_synced([event_id], status)
            elif status == "rejected":
                self._db.mark_rejected(event_id)
                logger.warning("Olay reddedildi eventId=%s", event_id)
            else:
                logger.warning("Bilinmeyen olay durumu %s", status)
        missing = [event.event_id or "" for event in batch if event.event_id not in seen]
        if missing:
            logger.warning("Yanıtta %s olay eksik, kuyrukta kaldı", len(missing))

    def _fail_web(self, batch: list[Event], reason: str) -> None:
        self._failures += 1
        delay = backoff_delay(self._failures, self._rng)
        self._next_web_at = time.monotonic() + delay
        self._next_heartbeat_at = max(self._next_heartbeat_at, self._next_web_at)
        ids = [event.event_id or "" for event in batch if event.event_id]
        self._db.mark_attempt_failed(ids)
        logger.warning("Web gönderimi ertelendi %.0f sn (%s)", delay, reason)

    def _succeed_web(self) -> None:
        self._failures = 0
        self._next_web_at = time.monotonic() + MIN_EVENT_GAP_SECONDS

    def _block_auth(self) -> None:
        self._auth_blocked = True
        self._db.set_state(STATE_AUTH_BLOCKED, "1")
        logger.error("Cihaz anahtarı reddedildi; gönderim durdu, olaylar kuyrukta")
        if self._on_auth_blocked is not None:
            self._on_auth_blocked()  # type: ignore[operator]

    def _is_auth_failure(self, response: httpx.Response) -> bool:
        if response.status_code == 401:
            return True
        text = response.text.casefold()
        return "unauthor" in text or "forbidden" in text or "revok" in text or "iptal" in text

    def _load_remote(self) -> RemoteConfig:
        raw = self._db.get_state(STATE_REMOTE_CONFIG)
        if not raw:
            return RemoteConfig()
        try:
            loaded = json.loads(raw)
        except json.JSONDecodeError:
            return RemoteConfig()
        if not isinstance(loaded, dict):
            return RemoteConfig()
        return RemoteConfig.from_mapping(loaded)


class SyncError(Exception):
    """Pairing or a caller-visible sync failure."""


def make_http_client() -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(REQUEST_TIMEOUT),
        verify=True,
        follow_redirects=False,
    )
