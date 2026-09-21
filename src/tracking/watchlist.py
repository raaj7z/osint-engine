from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any


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
    def __init__(self, db: Any = None, db_path: str | None = None):
        self.db = db
        self.db_path = db_path

    def add(
        self,
        actor_id: str,
        handle: str = "",
        identifiers: list[dict[str, Any]] | None = None,
        interval_minutes: int = 360,
        notes: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        interval_minutes = max(1, int(interval_minutes))

        if self.db is not None:
            watch_id = self.db.add_watchlist(
                actor_id=actor_id,
                interval_minutes=interval_minutes,
            )
            return watch_id

        raise RuntimeError("WatchlistStore requires the PRALAYX database")

    def remove(self, watch_id: str) -> None:
        if self.db is None:
            raise RuntimeError("WatchlistStore requires the PRALAYX database")

        self.db.remove_watchlist(watch_id)

    def pause(self, watch_id: str) -> None:
        self._set_state(watch_id, enabled=False)

    def resume(self, watch_id: str) -> None:
        self._set_state(watch_id, enabled=True)

    def get(self, watch_id: str) -> dict[str, Any] | None:
        if self.db is None:
            raise RuntimeError("WatchlistStore requires the PRALAYX database")

        for item in self.db.list_watchlist():
            if item.get("watch_id") == watch_id:
                return item

        return None

    def list(self) -> list[dict[str, Any]]:
        if self.db is None:
            raise RuntimeError("WatchlistStore requires the PRALAYX database")

        return self.db.list_watchlist()

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

    def mark_scanned(self, watch_id: str) -> None:
        item = self.get(watch_id)

        if not item:
            return

        interval = max(
            1,
            int(item.get("interval_minutes") or 360),
        )

        self._update(
            watch_id,
            last_scan_at=iso_now(),
            next_scan_at=(
                utc_now() + timedelta(minutes=interval)
            ).isoformat(),
        )

    def stats(self) -> dict[str, int]:
        items = self.list()

        active = [
            item for item in items
            if self._is_active(item)
        ]

        paused = [
            item for item in items
            if str(item.get("enabled", "")).lower()
            in {"0", "false", "none"}
        ]

        return {
            "total": len(items),
            "active": len(active),
            "paused": len(paused),
            "due": len(self.due()),
        }

    def _is_active(self, item: dict[str, Any]) -> bool:
        enabled = item.get("enabled", True)

        if isinstance(enabled, str):
            enabled = enabled.lower() not in {
                "0",
                "false",
                "no",
                "disabled",
            }

        return bool(enabled)

    def _is_due(self, item: dict[str, Any]) -> bool:
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
                    tzinfo=timezone.utc,
                )

            return parsed <= utc_now()

        except (TypeError, ValueError):
            return True

    def _set_state(
        self,
        watch_id: str,
        enabled: bool,
    ) -> None:
        self._update(
            watch_id,
            enabled=1 if enabled else 0,
        )

    def _update(
        self,
        watch_id: str,
        **fields: Any,
    ) -> None:
        if self.db is None:
            raise RuntimeError("WatchlistStore requires the PRALAYX database")

        allowed = {
            "enabled",
            "last_scan_at",
            "next_scan_at",
            "interval_minutes",
        }

        updates = {
            key: value
            for key, value in fields.items()
            if key in allowed
        }

        if not updates:
            return

        try:
            self.db.execute(
                """
                UPDATE sih_watchlist
                SET
                    enabled = COALESCE(?, enabled),
                    last_scan_at = COALESCE(?, last_scan_at),
                    next_scan_at = COALESCE(?, next_scan_at),
                    interval_minutes = COALESCE(?, interval_minutes),
                    updated_at = ?
                WHERE watch_id = ?
                """,
                (
                    updates.get("enabled"),
                    updates.get("last_scan_at"),
                    updates.get("next_scan_at"),
                    updates.get("interval_minutes"),
                    iso_now(),
                    watch_id,
                ),
            )
        except Exception:
            try:
                self.db.conn.rollback()
            except Exception:
                pass
            raise


__all__ = [
    "WatchlistEntry",
    "WatchlistStore",
]
