"""SQLite event queue, state, and the Firestore test outbox."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from pcmonitor.models import PROCESS_EVENT_TYPES, Event, utc_now

STATE_CLEAN_EXIT = "cleanExit"
STATE_LAST_ALIVE = "lastAliveUtc"
STATE_SEQ = "seqCounter"
STATE_RUNNING_APPS = "runningApps"
STATE_CONFIG_VERSION = "configVersion"
STATE_REMOTE_CONFIG = "remoteConfig"
STATE_LAST_BOOT = "lastBootTimeUtc"
STATE_LAST_SYNC = "lastSyncUtc"
STATE_AUTH_BLOCKED = "authBlocked"
STATE_DEVICE_ID = "deviceId"
STATE_PAUSED = "trackingPaused"
STATE_SHUTDOWN_RECORDED = "shutdownRecorded"

MAX_UNSYNCED = 200_000
PURGE_DAYS = 7

_SCHEMA = """
CREATE TABLE IF NOT EXISTS Events (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    EventId TEXT NOT NULL UNIQUE,
    Seq INTEGER NOT NULL UNIQUE,
    EventType TEXT NOT NULL,
    ProcessName TEXT,
    DisplayName TEXT,
    SessionKey TEXT,
    DurationSeconds INTEGER,
    Flags TEXT NOT NULL DEFAULT '{}',
    OccurredAtUtc TEXT NOT NULL,
    CreatedAtUtc TEXT NOT NULL,
    IsSynced INTEGER NOT NULL DEFAULT 0,
    SyncedAtUtc TEXT,
    Attempts INTEGER NOT NULL DEFAULT 0,
    SyncResult TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_pending ON Events(IsSynced, Seq);

CREATE TABLE IF NOT EXISTS State (
    Key TEXT PRIMARY KEY,
    Value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS FirestoreOutbox (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    IdempotencyKey TEXT NOT NULL UNIQUE,
    Kind TEXT NOT NULL,
    DocumentPath TEXT NOT NULL,
    Payload TEXT NOT NULL,
    IsSynced INTEGER NOT NULL DEFAULT 0,
    Attempts INTEGER NOT NULL DEFAULT 0,
    LastError TEXT,
    CreatedAtUtc TEXT NOT NULL,
    SyncedAtUtc TEXT
);
CREATE INDEX IF NOT EXISTS idx_firestore_pending ON FirestoreOutbox(IsSynced, Id);
"""


class Database:
    """One connection, one lock. Every writer goes through this object."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            path,
            check_same_thread=False,
            isolation_level="DEFERRED",
            timeout=5,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA journal_size_limit=1048576")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def add_event(self, event: Event) -> Event:
        with self._lock:
            event_id = event.event_id or str(uuid.uuid4())
            seq = self._next_seq_locked()
            created = utc_now()
            flags = json.dumps(event.flags, ensure_ascii=False, separators=(",", ":"))
            self._conn.execute(
                """
                INSERT INTO Events (
                    EventId, Seq, EventType, ProcessName, DisplayName, SessionKey,
                    DurationSeconds, Flags, OccurredAtUtc, CreatedAtUtc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    seq,
                    event.event_type,
                    event.process_name,
                    event.display_name,
                    event.session_key,
                    event.duration_seconds,
                    flags,
                    event.occurred_at_utc,
                    created,
                ),
            )
            self._conn.commit()
        event.event_id = event_id
        event.seq = seq
        event.created_at_utc = created
        return event

    def pending_events(self, limit: int) -> list[Event]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM Events
                WHERE IsSynced = 0
                ORDER BY Seq
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [_event_from_row(row) for row in rows]

    def pending_count(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM Events WHERE IsSynced = 0"
            ).fetchone()
        return int(row["n"])

    def mark_synced(self, event_ids: list[str], result: str) -> None:
        if not event_ids:
            return
        now = utc_now()
        with self._lock:
            self._conn.executemany(
                """
                UPDATE Events
                SET IsSynced = 1, SyncedAtUtc = ?, SyncResult = ?, Attempts = Attempts + 1
                WHERE EventId = ?
                """,
                [(now, result, event_id) for event_id in event_ids],
            )
            self._conn.commit()

    def mark_rejected(self, event_id: str) -> None:
        self.mark_synced([event_id], "rejected")

    def mark_attempt_failed(self, event_ids: list[str]) -> None:
        if not event_ids:
            return
        with self._lock:
            self._conn.executemany(
                "UPDATE Events SET Attempts = Attempts + 1 WHERE EventId = ?",
                [(event_id,) for event_id in event_ids],
            )
            self._conn.commit()

    def purge_synced(self, older_than_days: int = PURGE_DAYS) -> int:
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=older_than_days)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._lock:
            cursor = self._conn.execute(
                """
                DELETE FROM Events
                WHERE IsSynced = 1 AND SyncedAtUtc IS NOT NULL AND SyncedAtUtc < ?
                """,
                (cutoff,),
            )
            self._conn.commit()
            return int(cursor.rowcount)

    def enforce_cap(self, max_unsynced: int = MAX_UNSYNCED) -> str | None:
        """Collapse oldest unsynced process events when the queue is too large."""
        with self._lock:
            pending = int(
                self._conn.execute(
                    "SELECT COUNT(*) AS n FROM Events WHERE IsSynced = 0"
                ).fetchone()["n"]
            )
            if pending <= max_unsynced:
                return None
            overflow = pending - max_unsynced
            batch = min(max(overflow, 1), 1000)
            rows = self._conn.execute(
                """
                SELECT Id FROM Events
                WHERE IsSynced = 0
                  AND EventType IN ('process_started', 'process_stopped')
                  AND IFNULL(ProcessName, '') != '*'
                ORDER BY Seq
                LIMIT ?
                """,
                (batch,),
            ).fetchall()
            if not rows:
                return (
                    "Kuyruk üst sınıra ulaştı; sistem olayları korunuyor, "
                    "özetlenecek süreç olayı kalmadı"
                )
            ids = [int(row["Id"]) for row in rows]
            placeholders = ",".join("?" for _ in ids)
            self._conn.execute(
                f"DELETE FROM Events WHERE Id IN ({placeholders})",
                ids,
            )
            seq = self._next_seq_locked()
            event_id = str(uuid.uuid4())
            now = utc_now()
            flags = json.dumps(
                {"initial": False, "inferred": True, "summary": True, "collapsed": len(ids)},
                separators=(",", ":"),
            )
            self._conn.execute(
                """
                INSERT INTO Events (
                    EventId, Seq, EventType, ProcessName, DisplayName, SessionKey,
                    DurationSeconds, Flags, OccurredAtUtc, CreatedAtUtc
                ) VALUES (?, ?, 'process_stopped', '*', 'Özet', NULL, NULL, ?, ?, ?)
                """,
                (event_id, seq, flags, now, now),
            )
            self._conn.commit()
        return f"{len(ids)} süreç olayı özete indirildi"

    def get_state(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT Value FROM State WHERE Key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        return str(row["Value"])

    def set_state(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO State (Key, Value) VALUES (?, ?)
                ON CONFLICT(Key) DO UPDATE SET Value = excluded.Value
                """,
                (key, value),
            )
            self._conn.commit()

    def enqueue_firestore(
        self,
        *,
        idempotency_key: str,
        kind: str,
        document_path: str,
        payload: dict[str, str],
        reset_if_exists: bool,
    ) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        now = utc_now()
        with self._lock:
            if reset_if_exists:
                self._conn.execute(
                    """
                    INSERT INTO FirestoreOutbox (
                        IdempotencyKey, Kind, DocumentPath, Payload, CreatedAtUtc
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(IdempotencyKey) DO UPDATE SET
                        Kind = excluded.Kind,
                        DocumentPath = excluded.DocumentPath,
                        Payload = excluded.Payload,
                        IsSynced = 0,
                        SyncedAtUtc = NULL,
                        LastError = NULL
                    """,
                    (idempotency_key, kind, document_path, encoded, now),
                )
            else:
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO FirestoreOutbox (
                        IdempotencyKey, Kind, DocumentPath, Payload, CreatedAtUtc
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (idempotency_key, kind, document_path, encoded, now),
                )
            self._conn.commit()

    def pending_firestore(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM FirestoreOutbox
                WHERE IsSynced = 0
                ORDER BY Id
                """
            ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            payload = json.loads(row["Payload"])
            items.append(
                {
                    "id": int(row["Id"]),
                    "idempotencyKey": row["IdempotencyKey"],
                    "kind": row["Kind"],
                    "documentPath": row["DocumentPath"],
                    "payload": payload,
                    "attempts": int(row["Attempts"]),
                }
            )
        return items

    def mark_firestore_synced(self, row_id: int) -> None:
        now = utc_now()
        with self._lock:
            self._conn.execute(
                """
                UPDATE FirestoreOutbox
                SET IsSynced = 1, SyncedAtUtc = ?, LastError = NULL,
                    Attempts = Attempts + 1
                WHERE Id = ?
                """,
                (now, row_id),
            )
            self._conn.commit()

    def mark_firestore_failed(self, row_id: int, error: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE FirestoreOutbox
                SET Attempts = Attempts + 1, LastError = ?
                WHERE Id = ?
                """,
                (error[:300], row_id),
            )
            self._conn.commit()

    def _next_seq_locked(self) -> int:
        row = self._conn.execute(
            "SELECT Value FROM State WHERE Key = ?",
            (STATE_SEQ,),
        ).fetchone()
        current = int(row["Value"]) if row is not None else 0
        nxt = current + 1
        self._conn.execute(
            """
            INSERT INTO State (Key, Value) VALUES (?, ?)
            ON CONFLICT(Key) DO UPDATE SET Value = excluded.Value
            """,
            (STATE_SEQ, str(nxt)),
        )
        return nxt


def _event_from_row(row: sqlite3.Row) -> Event:
    try:
        flags = json.loads(row["Flags"])
    except json.JSONDecodeError:
        flags = {}
    if not isinstance(flags, dict):
        flags = {}
    duration = row["DurationSeconds"]
    return Event(
        event_id=row["EventId"],
        seq=int(row["Seq"]),
        event_type=row["EventType"],
        process_name=row["ProcessName"],
        display_name=row["DisplayName"],
        session_key=row["SessionKey"],
        duration_seconds=None if duration is None else int(duration),
        flags=flags,
        occurred_at_utc=row["OccurredAtUtc"],
        created_at_utc=row["CreatedAtUtc"],
        is_synced=bool(row["IsSynced"]),
        attempts=int(row["Attempts"]),
        sync_result=row["SyncResult"],
    )


def is_process_event(event_type: str) -> bool:
    return event_type in PROCESS_EVENT_TYPES
