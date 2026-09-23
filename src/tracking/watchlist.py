from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
import uuid


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat()


@dataclass
class WatchlistEntry:
    actor_id: str
    handle: str = ""
    identifiers: list[dict[str, Any]] = field(default_factory=list)
    interval_minutes: int = 360
    status: str = "ACTIVE"
    added_at: str = field(default_factory=iso_now)
    last_scanned: str | None = None
    next_scan: str | None = None
    notes: str = ""
    scan_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


class WatchlistStore:
    def __init__(
        self,
        db: Any = None,
        db_path: str | None = None,
    ):
        self.db = db
        self.db_path = db_path

        if self.db is None:
            raise RuntimeError(
                "WatchlistStore requires the PRALAYX database"
            )

        self._ensure_table()

    def _ensure_table(self) -> None:
        self.db.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sih_watchlist (
                watch_id TEXT PRIMARY KEY,
                actor_id TEXT NOT NULL,
                handle TEXT DEFAULT '',
                identifiers TEXT DEFAULT '[]',
                investigation_id TEXT,
                interval_minutes INTEGER DEFAULT 360,
                enabled INTEGER DEFAULT 1,
                status TEXT DEFAULT 'ACTIVE',
                added_at TEXT NOT NULL,
                last_scan_at TEXT,
                next_scan_at TEXT,
                notes TEXT DEFAULT '',
                scan_count INTEGER DEFAULT 0,
                metadata TEXT DEFAULT '{}',
                updated_at TEXT NOT NULL
            )
            """
        )

        self.db.conn.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_sih_watchlist_actor
            ON sih_watchlist(actor_id)
            """
        )

        self.db.conn.commit()

    @staticmethod
    def _json(value: Any) -> str:
        import json

        return json.dumps(
            value,
            ensure_ascii=False,
            default=str,
        )

    @staticmethod
    def _loads(value: Any, default: Any) -> Any:
        import json

        if value is None:
            return default

        try:
            return json.loads(value)
        except (
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):
            return default

    def add(
        self,
        actor_id: str,
        handle: str = "",
        identifiers: list[dict[str, Any]] | None = None,
        interval_minutes: int = 360,
        notes: str = "",
        metadata: dict[str, Any] | None = None,
        investigation_id: str | None = None,
    ) -> str:

        if not actor_id:
            raise ValueError(
                "actor_id is required"
            )

        interval_minutes = max(
            1,
            int(interval_minutes),
        )

        watch_id = (
            f"WATCH-{uuid.uuid4().hex[:12].upper()}"
        )

        now = utc_now()

        next_scan = (
            now
            + timedelta(
                minutes=interval_minutes
            )
        ).isoformat()

        self.db.conn.execute(
            """
            INSERT INTO sih_watchlist
            (
                watch_id,
                actor_id,
                handle,
                identifiers,
                investigation_id,
                interval_minutes,
                enabled,
                status,
                added_at,
                next_scan_at,
                notes,
                scan_count,
                metadata,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 1, 'ACTIVE',
                    ?, ?, ?, 0, ?, ?)
            """,
            (
                watch_id,
                actor_id,
                handle or actor_id,
                self._json(
                    identifiers or []
                ),
                investigation_id,
                interval_minutes,
                now.isoformat(),
                next_scan,
                notes,
                self._json(
                    metadata or {}
                ),
                now.isoformat(),
            ),
        )

        self.db.conn.commit()

        return watch_id

    def remove(
        self,
        watch_id: str,
    ) -> None:

        self.db.conn.execute(
            """
            DELETE FROM sih_watchlist
            WHERE watch_id = ?
            """,
            (watch_id,),
        )

        self.db.conn.commit()

    def pause(
        self,
        watch_id: str,
    ) -> None:
        self._set_state(
            watch_id,
            enabled=False,
        )

    def resume(
        self,
        watch_id: str,
    ) -> None:
        self._set_state(
            watch_id,
            enabled=True,
        )

    def get(
        self,
        watch_id: str,
    ) -> dict[str, Any] | None:

        row = self.db.conn.execute(
            """
            SELECT *
            FROM sih_watchlist
            WHERE watch_id = ?
            """,
            (watch_id,),
        ).fetchone()

        if not row:
            return None

        return self._row_to_dict(row)

    def list(self) -> list[dict[str, Any]]:

        rows = self.db.conn.execute(
            """
            SELECT *
            FROM sih_watchlist
            ORDER BY added_at DESC
            """
        ).fetchall()

        return [
            self._row_to_dict(row)
            for row in rows
        ]

    def all_active(self) -> list[dict[str, Any]]:
        return self.active()

    def active(self) -> list[dict[str, Any]]:
        return [
            item
            for item in self.list()
            if self._is_active(item)
        ]

    def due(self) -> list[dict[str, Any]]:
        return [
            item
            for item in self.active()
            if self._is_due(item)
        ]

    def mark_scanned(
        self,
        watch_id: str,
    ) -> None:

        item = self.get(watch_id)

        if not item:
            return

        interval = max(
            1,
            int(
                item.get(
                    "interval_minutes",
                    360,
                )
                or 360
            ),
        )

        now = utc_now()

        self.db.conn.execute(
            """
            UPDATE sih_watchlist
            SET
                last_scan_at = ?,
                next_scan_at = ?,
                scan_count = scan_count + 1,
                updated_at = ?
            WHERE watch_id = ?
            """,
            (
                now.isoformat(),
                (
                    now
                    + timedelta(
                        minutes=interval
                    )
                ).isoformat(),
                now.isoformat(),
                watch_id,
            ),
        )

        self.db.conn.commit()

    def stats(self) -> dict[str, int]:
        items = self.list()

        active = [
            item
            for item in items
            if self._is_active(item)
        ]

        paused = [
            item
            for item in items
            if not self._is_active(item)
        ]

        due = [
            item
            for item in active
            if self._is_due(item)
        ]

        return {
            "total": len(items),
            "active": len(active),
            "paused": len(paused),
            "due": len(due),
        }

    def get_stats(self) -> dict[str, int]:
        return self.stats()

    def _set_state(
        self,
        watch_id: str,
        enabled: bool,
    ) -> None:

        now = iso_now()

        self.db.conn.execute(
            """
            UPDATE sih_watchlist
            SET
                enabled = ?,
                status = ?,
                updated_at = ?
            WHERE watch_id = ?
            """,
            (
                1 if enabled else 0,
                "ACTIVE" if enabled else "PAUSED",
                now,
                watch_id,
            ),
        )

        self.db.conn.commit()

    def _update(
        self,
        watch_id: str,
        **fields: Any,
    ) -> None:

        allowed = {
            "enabled",
            "last_scan_at",
            "next_scan_at",
            "interval_minutes",
            "status",
            "notes",
            "handle",
            "identifiers",
            "metadata",
        }

        updates = {
            key: value
            for key, value in fields.items()
            if key in allowed
        }

        if not updates:
            return

        assignments = []
        values = []

        for key, value in updates.items():

            if key in {
                "identifiers",
                "metadata",
            }:
                value = self._json(value)

            assignments.append(
                f"{key} = ?"
            )
            values.append(value)

        assignments.append(
            "updated_at = ?"
        )
        values.append(
            iso_now()
        )

        values.append(
            watch_id
        )

        self.db.conn.execute(
            f"""
            UPDATE sih_watchlist
            SET {", ".join(assignments)}
            WHERE watch_id = ?
            """,
            tuple(values),
        )

        self.db.conn.commit()

    def _is_active(
        self,
        item: dict[str, Any],
    ) -> bool:

        enabled = item.get(
            "enabled",
            True,
        )

        if isinstance(
            enabled,
            str,
        ):
            enabled = (
                enabled.lower()
                not in {
                    "0",
                    "false",
                    "no",
                    "disabled",
                }
            )

        return bool(enabled)

    def _is_due(
        self,
        item: dict[str, Any],
    ) -> bool:

        if not self._is_active(item):
            return False

        next_scan = (
            item.get("next_scan_at")
            or item.get("next_scan")
        )

        if not next_scan:
            return True

        try:
            parsed = datetime.fromisoformat(
                str(next_scan).replace(
                    "Z",
                    "+00:00",
                )
            )

            if parsed.tzinfo is None:
                parsed = parsed.replace(
                    tzinfo=timezone.utc
                )

            return parsed <= utc_now()

        except (
            TypeError,
            ValueError,
        ):
            return True

    def _row_to_dict(
        self,
        row: Any,
    ) -> dict[str, Any]:

        item = dict(row)

        item["identifiers"] = self._loads(
            item.get("identifiers"),
            [],
        )

        item["metadata"] = self._loads(
            item.get("metadata"),
            {},
        )

        item["next_scan"] = item.get(
            "next_scan_at"
        )

        item["last_scanned"] = item.get(
            "last_scan_at"
        )

        item["active"] = self._is_active(
            item
        )

        return item


__all__ = [
    "WatchlistEntry",
    "WatchlistStore",
]
