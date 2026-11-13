"""Temporary direct Firestore writes used to test the agent on several PCs.

The permanent path remains the web API in sync_client.py. This module is the
only place that talks to Firestore. The API key is read from config.json.

Firestore document layout
  machines/{machineGuid}             ← machine snapshot (PATCH)
  machines/{machineGuid}/logins/{id} ← login record per start (POST)
  machines/{machineGuid}/events/{id} ← process/system events (POST)
  machines/{machineGuid}/appStats/{appKey} ← per-app stats (PATCH)
  machines/{machineGuid}/state/current    ← agent state (PATCH)

Each machine only ever touches its own machineGuid document; it never
modifies any other machine's data.
"""

from __future__ import annotations

import getpass
import logging
import platform
import socket
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from pcmonitor import __version__
from pcmonitor.config import Settings, console_print
from pcmonitor.db import Database
from pcmonitor.models import Event, local_now, utc_now

logger = logging.getLogger(__name__)

_FIRESTORE_ROOT = "https://firestore.googleapis.com/v1"

# Idempotency key prefix for the per-machine snapshot row in FirestoreOutbox
_MACHINE_KEY = "machine:{guid}"

# Fields written to the logins sub-collection (order preserved for _string_fields)
_LOGIN_FIELDS = (
    "event",
    "machineGuid",
    "username",
    "computerName",
    "osVersion",
    "agentVersion",
    "startedAtUtc",
    "startedAtLocal",
)

# Fields written to the machines/{machineGuid} document via PATCH + updateMask
# "label" is included so the web panel can filter/group by machine label.
_MACHINE_FIELDS = ("machineGuid", "computerName", "username", "label", "lastSeenUtc")


class MachineIdError(Exception):
    """MachineGuid could not be read from the registry."""


@dataclass
class WriteStatus:
    ok: bool
    duplicate: bool
    retriable: bool
    message: str


@dataclass
class MachineFacts:
    machine_guid: str
    username: str
    computer_name: str
    os_version: str
    agent_version: str
    started_at_utc: str
    started_at_local: str
    label: str  # "PC 1", "PC 2", etc.; falls back to computer_name when empty

    @property
    def effective_label(self) -> str:
        """Return the configured label, or computer_name as fallback."""
        return self.label if self.label else self.computer_name

    def login_payload(self) -> dict[str, str]:
        """Fields for the logins sub-collection entry.

        Note: label is intentionally NOT included here per spec.
        """
        return {
            "event": "agent_started",
            "machineGuid": self.machine_guid,
            "username": self.username,
            "computerName": self.computer_name,
            "osVersion": self.os_version,
            "agentVersion": self.agent_version,
            "startedAtUtc": self.started_at_utc,
            "startedAtLocal": self.started_at_local,
        }

    def machine_payload(self) -> dict[str, str]:
        """Fields for the machines/{machineGuid} snapshot document."""
        return {
            "machineGuid": self.machine_guid,
            "computerName": self.computer_name,
            "username": self.username,
            "label": self.effective_label,
            "lastSeenUtc": self.started_at_utc,
        }

    def summary_prefix(self) -> str:
        """Human-readable one-liner for console and log output."""
        return (
            f"etiket={self.effective_label} machineGuid={self.machine_guid} "
            f"kullanıcı={self.username} bilgisayar={self.computer_name} "
            f"utc={self.started_at_utc} yerel={self.started_at_local}"
        )


def read_machine_guid() -> str:
    """Read the Windows MachineGuid from the registry.

    Uses KEY_READ | KEY_WOW64_64KEY so the 64-bit hive is always reached
    even when running from a 32-bit Python interpreter.
    Raises MachineIdError if the value cannot be read.
    """
    import winreg  # only available on Windows

    access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            access,
        ) as key:
            value, _kind = winreg.QueryValueEx(key, "MachineGuid")
    except OSError as exc:
        raise MachineIdError(f"MachineGuid okunamadı: {exc}") from exc
    guid = str(value).strip()
    if not guid:
        raise MachineIdError("MachineGuid boş")
    return guid


def collect_machine_facts(settings: Settings | None = None) -> MachineFacts:
    """Gather all machine identity fields in one call."""
    label = settings.label if settings is not None else ""
    return MachineFacts(
        machine_guid=read_machine_guid(),
        username=getpass.getuser(),
        computer_name=socket.gethostname(),
        os_version=platform.platform(),
        agent_version=__version__,
        started_at_utc=utc_now(),
        started_at_local=local_now(),
        label=label,
    )


def enqueue_startup(database: Database, facts: MachineFacts) -> str:
    """Store one login record and refresh the machine snapshot in the outbox.

    The login row uses a fresh UUID as idempotency key so every agent start
    produces exactly one new record.  The machine snapshot row is keyed on the
    machineGuid and is overwritten (reset_if_exists=True) each time — only
    one pending snapshot per machine is kept.

    Returns the login document id (UUID string).
    """
    login_id = str(uuid.uuid4())
    login_path = f"machines/{quote(facts.machine_guid, safe='')}/logins/{login_id}"
    machine_path = f"machines/{quote(facts.machine_guid, safe='')}"

    # Login entry: each start creates a new document, never overwritten.
    database.enqueue_firestore(
        idempotency_key=login_id,
        kind="login",
        document_path=login_path,
        payload=facts.login_payload(),
        reset_if_exists=False,
    )

    # Machine snapshot: always reflect the latest state; previous pending row
    # (if unsent) is replaced so we don't send stale data.
    database.enqueue_firestore(
        idempotency_key=_MACHINE_KEY.format(guid=facts.machine_guid),
        kind="machine",
        document_path=machine_path,
        payload=facts.machine_payload(),
        reset_if_exists=True,
    )
    return login_id


class FirestoreRest:
    """Thin wrapper around the Firestore REST API (no Firebase SDK required)."""

    def __init__(self, project_id: str, api_key: str, client: httpx.Client) -> None:
        self.project_id = project_id
        self.api_key = api_key
        self._client = client

    def send(self, kind: str, document_path: str, payload: dict[str, str]) -> WriteStatus:
        """Dispatch to the correct REST method based on the row kind."""
        if not self.project_id or not self.api_key:
            return WriteStatus(False, False, True, "Firestore ayarı yok (projectId veya apiKey eksik)")
        if kind == "login":
            return self._create_login(document_path, payload)
        if kind == "machine":
            return self._upsert_machine(document_path, payload)
        return WriteStatus(False, False, False, f"bilinmeyen tür: {kind}")

    # ------------------------------------------------------------------
    # Login  (POST to parent collection with explicit documentId)
    # ------------------------------------------------------------------

    def _create_login(self, document_path: str, payload: dict[str, str]) -> WriteStatus:
        """POST machines/{guid}/logins?documentId={loginId}"""
        parent, _slash, doc_id = document_path.rpartition("/")
        url = self._documents_url(parent)
        try:
            response = self._client.post(
                url,
                params={"documentId": doc_id, "key": self.api_key},
                json={"fields": _string_fields(payload, _LOGIN_FIELDS)},
            )
        except httpx.HTTPError as exc:
            return WriteStatus(False, False, True, redact(str(exc), self.api_key))

        if response.status_code == 409 or _already_exists(response):
            return WriteStatus(True, True, False, "zaten vardı")
        if response.status_code < 400:
            return WriteStatus(True, False, False, f"yazıldı HTTP {response.status_code}")
        return _http_status(response, self.api_key)

    # ------------------------------------------------------------------
    # Machine snapshot  (PATCH with updateMask, falls back to POST)
    # ------------------------------------------------------------------

    def _upsert_machine(self, document_path: str, payload: dict[str, str]) -> WriteStatus:
        """PATCH machines/{guid} with updateMask for the allowed fields only."""
        url = self._documents_url(document_path)
        # Build updateMask query params: one entry per field name.
        params: list[tuple[str, str]] = [
            ("updateMask.fieldPaths", name) for name in _MACHINE_FIELDS
        ]
        params.append(("key", self.api_key))
        try:
            response = self._client.patch(
                url,
                params=params,
                json={"fields": _string_fields(payload, _MACHINE_FIELDS)},
            )
        except httpx.HTTPError as exc:
            return WriteStatus(False, False, True, redact(str(exc), self.api_key))

        if response.status_code < 400:
            return WriteStatus(True, False, False, f"güncellendi HTTP {response.status_code}")
        # Firestore PATCH with updateMask on a non-existent document returns
        # 200 (creates it) in most regions, but fall back to POST just in case.
        if response.status_code == 404:
            return self._create_machine(document_path, payload)
        return _http_status(response, self.api_key)

    def _create_machine(self, document_path: str, payload: dict[str, str]) -> WriteStatus:
        """POST machines/{guid} when PATCH 404-ed (document does not yet exist)."""
        parent, _slash, doc_id = document_path.rpartition("/")
        url = self._documents_url(parent or "machines")
        try:
            response = self._client.post(
                url,
                params={"documentId": doc_id, "key": self.api_key},
                json={"fields": _string_fields(payload, _MACHINE_FIELDS)},
            )
        except httpx.HTTPError as exc:
            return WriteStatus(False, False, True, redact(str(exc), self.api_key))

        already = response.status_code == 409 or _already_exists(response)
        if response.status_code < 400 or already:
            return WriteStatus(True, already, False, "oluşturuldu")
        return _http_status(response, self.api_key)

    # ------------------------------------------------------------------
    # URL helpers
    # ------------------------------------------------------------------

    def _documents_url(self, relative_path: str) -> str:
        """Build a full Firestore REST documents URL from a relative path.

        Example:
            relative_path="machines/abc123/logins"
            → https://firestore.googleapis.com/v1/projects/pcmonitors/
              databases/(default)/documents/machines/abc123/logins
        """
        project = quote(self.project_id, safe="")
        # Split on "/" and percent-encode each segment individually so that
        # GUIDs containing hyphens remain intact while special chars are safe.
        suffix = "/".join(quote(part, safe="") for part in relative_path.split("/") if part)
        return (
            f"{_FIRESTORE_ROOT}/projects/{project}"
            f"/databases/(default)/documents/{suffix}"
        )


def flush_outbox(database: Database, rest: "FirestoreRest") -> str:
    """Drain pending outbox rows, one at a time.

    Stops early on retriable errors (network down, 5xx) so the rows remain
    queued for the next attempt.  Non-retriable errors (bad config, unknown
    kind) are logged and skipped.

    Returns a human-readable summary string; starts with "başarılı" on
    full success so callers can test ``result.startswith("başarılı")``.
    """
    pending = database.pending_firestore()
    if not pending:
        return "kuyruk boş"

    sent = 0
    duplicates = 0
    failure: str | None = None
    retriable = False

    for item in pending:
        status = rest.send(item["kind"], item["documentPath"], item["payload"])
        if status.ok:
            database.mark_firestore_synced(int(item["id"]))
            sent += 1
            if status.duplicate:
                duplicates += 1
            continue

        # Persist the error message for diagnostics, then decide whether to stop.
        database.mark_firestore_failed(int(item["id"]), status.message)
        failure = status.message
        retriable = status.retriable
        logger.warning("Firestore yazılamadı: %s", status.message)
        if status.retriable:
            # Network / server error — stop and retry the whole batch later.
            break
        # Non-retriable (e.g. unknown kind): log and continue with next row.

    if failure and sent:
        return f"kısmen başarılı, kuyrukta kaldı ({failure})"
    if failure and retriable:
        return f"kuyruğa alındı ({failure})"
    if failure:
        return f"hata: {failure}"
    if duplicates and duplicates == sent:
        return "başarılı (zaten vardı)"
    return "başarılı"


def announce_startup(
    database: Database,
    settings: Settings,
    client: httpx.Client | None = None,
    facts: MachineFacts | None = None,
) -> str:
    """Queue this agent start and attempt an immediate write.

    If the write fails, the rows stay in the outbox and are retried by the
    background sync loop.  This function is safe to call without a network
    connection.

    Returns a single log-safe line (API key is redacted).
    """
    try:
        identity = facts or collect_machine_facts(settings)
    except MachineIdError as exc:
        line = f"machineGuid=okunamadı firestore=hata: {exc}"
        logger.error(line)
        console_print(line)
        return line

    enqueue_startup(database, identity)

    owns_client = client is None
    http = client or httpx.Client(
        timeout=httpx.Timeout(10.0),
        verify=True,
        follow_redirects=False,
    )
    try:
        rest = FirestoreRest(
            settings.firestore_project_id,
            settings.firestore_api_key,
            http,
        )
        result = flush_outbox(database, rest)
    finally:
        if owns_client:
            http.close()

    line = f"{identity.summary_prefix()} firestore={result}"
    if result.startswith("başarılı"):
        logger.info(line)
    else:
        logger.warning(line)
    console_print(line)
    return line


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def redact(text: str, api_key: str) -> str:
    """Remove the API key from error messages before logging/storing."""
    cleaned = text.replace(api_key, "***") if api_key else text
    return cleaned[:300]


def _string_fields(payload: dict[str, str], names: tuple[str, ...]) -> dict[str, Any]:
    """Wrap values in Firestore's typed ``stringValue`` envelope."""
    return {name: {"stringValue": str(payload.get(name, ""))} for name in names}


def _already_exists(response: httpx.Response) -> bool:
    """Return True when the Firestore response body signals ALREADY_EXISTS."""
    try:
        body = response.json()
    except ValueError:
        return False
    error = body.get("error") if isinstance(body, dict) else None
    if not isinstance(error, dict):
        return False
    return str(error.get("status") or "") == "ALREADY_EXISTS"


def _http_status(response: httpx.Response, api_key: str) -> WriteStatus:
    """Convert a non-2xx response to a WriteStatus."""
    retriable = response.status_code in {408, 429} or response.status_code >= 500
    # 401/403 are auth errors; mark retriable so the row is not discarded —
    # the user may fix credentials and restart.
    if response.status_code in {401, 403}:
        retriable = True
    message = redact(f"HTTP {response.status_code} {response.text[:200]}", api_key)
    return WriteStatus(False, False, retriable, message)


# ---------------------------------------------------------------------------
# Olay / uygulama istatistikleri Firestore'a doğrudan yazma
# ---------------------------------------------------------------------------

_APP_KEY_TRANS = str.maketrans(".", "_")


def _to_app_key(process_name: str) -> str:
    """appStats koleksiyonu için doküman kimliği: küçük harf, '.' → '_'"""
    return process_name.lower().translate(_APP_KEY_TRANS)


def write_event_to_firestore(
    rest: FirestoreRest,
    machine_guid: str,
    event: Event,
) -> WriteStatus:
    """Tek bir olayı machines/{guid}/events/{eventId} olarak yazar."""
    event_id = event.event_id or str(uuid.uuid4())
    doc_path = f"machines/{quote(machine_guid, safe='')}/events/{event_id}"
    url = rest._documents_url(doc_path)

    # Firestore Timestamp için RFC3339 string kullanıyoruz (REST API kabul eder)
    fields: dict[str, Any] = {
        "eventId":        {"stringValue": event_id},
        "eventType":      {"stringValue": event.event_type},
        "occurredAt":     {"stringValue": event.occurred_at_utc},
        "seq":            {"integerValue": str(event.seq or 0)},
        "flags":          {"mapValue": {"fields": {
            "initial":  {"booleanValue": bool(event.flags.get("initial", False))},
            "inferred": {"booleanValue": bool(event.flags.get("inferred", False))},
        }}},
    }
    if event.process_name:
        fields["processName"]    = {"stringValue": event.process_name}
        fields["displayName"]    = {"stringValue": event.display_name or event.process_name}
        fields["sessionKey"]     = {"stringValue": event.session_key or ""}
        fields["category"]       = {"stringValue": getattr(event, "category", "app") or "app"}
    if event.duration_seconds is not None:
        fields["durationSeconds"] = {"integerValue": str(event.duration_seconds)}

    try:
        response = rest._client.post(
            rest._documents_url(
                f"machines/{quote(machine_guid, safe='')}/events"
            ),
            params={"documentId": event_id, "key": rest.api_key},
            json={"fields": fields},
        )
    except httpx.HTTPError as exc:
        return WriteStatus(False, False, True, redact(str(exc), rest.api_key))

    if response.status_code == 409 or _already_exists(response):
        return WriteStatus(True, True, False, "zaten vardı")
    if response.status_code < 400:
        return WriteStatus(True, False, False, f"yazıldı HTTP {response.status_code}")
    return _http_status(response, rest.api_key)


def write_app_stats_to_firestore(
    rest: FirestoreRest,
    machine_guid: str,
    event: Event,
) -> WriteStatus:
    """process_started / process_stopped olayına göre appStats dokümanını günceller."""
    if event.event_type not in ("process_started", "process_stopped"):
        return WriteStatus(True, False, False, "atlandı")
    if not event.process_name:
        return WriteStatus(True, False, False, "process_name yok")

    app_key = _to_app_key(event.process_name)
    doc_path = f"machines/{quote(machine_guid, safe='')}/appStats/{app_key}"
    url = rest._documents_url(doc_path)

    fields: dict[str, Any] = {
        "processName": {"stringValue": event.process_name},
        "displayName": {"stringValue": event.display_name or event.process_name},
    }

    if event.event_type == "process_started":
        fields["lastStartedAt"] = {"stringValue": event.occurred_at_utc}
        fields["isRunning"]     = {"booleanValue": True}
        # launchCount artırımı: Firestore REST'te increment için transform kullanmak gerek
        # Basit yaklaşım: önce oku, +1 yaz. Kota tasarrufu için sadece PATCH yapıyoruz.
        # isRunning=true ve lastStartedAt zaten yeterli panel için.
    else:
        fields["lastStoppedAt"] = {"stringValue": event.occurred_at_utc}
        fields["isRunning"]     = {"booleanValue": False}
        if event.duration_seconds is not None:
            fields["totalSeconds"] = {"integerValue": str(event.duration_seconds)}

    update_fields = list(fields.keys())
    params: list[tuple[str, str]] = [
        ("updateMask.fieldPaths", f) for f in update_fields
    ]
    params.append(("key", rest.api_key))

    try:
        response = rest._client.patch(
            url, params=params, json={"fields": fields}
        )
    except httpx.HTTPError as exc:
        return WriteStatus(False, False, True, redact(str(exc), rest.api_key))

    if response.status_code < 400:
        return WriteStatus(True, False, False, f"appStats güncellendi")
    # 404 → doküman yok, POST ile oluştur
    if response.status_code == 404:
        try:
            r2 = rest._client.post(
                rest._documents_url(
                    f"machines/{quote(machine_guid, safe='')}/appStats"
                ),
                params={"documentId": app_key, "key": rest.api_key},
                json={"fields": fields},
            )
        except httpx.HTTPError as exc:
            return WriteStatus(False, False, True, redact(str(exc), rest.api_key))
        if r2.status_code < 400 or r2.status_code == 409:
            return WriteStatus(True, r2.status_code == 409, False, "appStats oluşturuldu")
        return _http_status(r2, rest.api_key)
    return _http_status(response, rest.api_key)


def write_state_to_firestore(
    rest: FirestoreRest,
    machine_guid: str,
    agent_version: str,
    status: str = "running",
    pending_count: int = 0,
) -> WriteStatus:
    """machines/{guid}/state/current dokümanını günceller."""
    doc_path = f"machines/{quote(machine_guid, safe='')}/state/current"
    fields: dict[str, Any] = {
        "status":       {"stringValue": status},
        "lastSeenAt":   {"stringValue": utc_now()},
        "agentVersion": {"stringValue": agent_version},
        "pendingCount": {"integerValue": str(pending_count)},
    }
    update_fields = list(fields.keys())
    params: list[tuple[str, str]] = [
        ("updateMask.fieldPaths", f) for f in update_fields
    ]
    params.append(("key", rest.api_key))
    url = rest._documents_url(doc_path)
    try:
        response = rest._client.patch(
            url, params=params, json={"fields": fields}
        )
    except httpx.HTTPError as exc:
        return WriteStatus(False, False, True, redact(str(exc), rest.api_key))
    if response.status_code < 400:
        return WriteStatus(True, False, False, "state güncellendi")
    if response.status_code == 404:
        try:
            parent = f"machines/{quote(machine_guid, safe='')}/state"
            r2 = rest._client.post(
                rest._documents_url(parent),
                params={"documentId": "current", "key": rest.api_key},
                json={"fields": fields},
            )
        except httpx.HTTPError as exc:
            return WriteStatus(False, False, True, redact(str(exc), rest.api_key))
        return WriteStatus(r2.status_code < 400, False, False, "state oluşturuldu")
    return _http_status(response, rest.api_key)


def flush_events_direct(
    events: list[Event],
    machine_guid: str,
    rest: FirestoreRest,
) -> int:
    """Verilen olayları doğrudan Firestore'a yazar. Başarılı yazılan sayısını döner."""
    written = 0
    for event in events:
        # 1. Olay dokümanı
        status = write_event_to_firestore(rest, machine_guid, event)
        if status.ok:
            written += 1
            if not status.duplicate:
                logger.debug("Firestore olay yazıldı: %s %s", event.event_type, event.process_name)
        else:
            logger.warning("Firestore olay yazılamadı: %s", status.message)
            if status.retriable:
                break  # ağ hatası → dur

        # 2. appStats güncelle (process olayları için)
        if event.event_type in ("process_started", "process_stopped"):
            write_app_stats_to_firestore(rest, machine_guid, event)

    return written
