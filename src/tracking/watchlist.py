"""Persistent watchlist storage for tracked threat actors.

Actors on the watchlist are periodically re-scanned by the scheduler
based on each entry's configured interval.
"""

import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


@dataclass
class WatchlistEntry:
    """A single tracked actor and their scan configuration."""

    actor_id: str
    handle: str
    identifiers: list[dict] = field(default_factory=list)
    interval_hours: int = 6
    status: str = "ACTIVE"
    added_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_scanned: str | None = None
    next_scan: str | None = None
    notes: str = ""
    scan_count: int = 0


class WatchlistStore:
    """SQLite-backed store for watchlist entries."""

    def __init__(self, db_path: str = "data/watchlist.db"):
        """Open (or create) the watchlist database and ensure the table exists."""
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_table()

    def _create_table(self) -> None:
        """Create the watchlist table if it doesn't already exist."""
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS watchlist (
                actor_id TEXT PRIMARY KEY,
                handle TEXT,
                identifiers TEXT,
                interval_hours INTEGER DEFAULT 6,
                status TEXT DEFAULT 'ACTIVE',
                added_at TEXT,
                last_scanned TEXT,
                next_scan TEXT,
                notes TEXT DEFAULT '',
                scan_count INTEGER DEFAULT 0
            )
            """
        )
        self.conn.commit()

    def add(self, entry: WatchlistEntry) -> None:
        """Insert or replace a watchlist entry, computing its initial next_scan time."""
        if not entry.next_scan:
            entry.next_scan = (
                datetime.now(timezone.utc) + timedelta(hours=entry.interval_hours)
            ).isoformat()

        try:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO watchlist
                (actor_id, handle, identifiers, interval_hours, status,
                 added_at, last_scanned, next_scan, notes, scan_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.actor_id,
                    entry.handle,
                    json.dumps(entry.identifiers),
                    entry.interval_hours,
                    entry.status,
                    entry.added_at,
                    entry.last_scanned,
                    entry.next_scan,
                    entry.notes,
                    entry.scan_count,
                ),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()

    def remove(self, actor_id: str) -> None:
        """Mark an actor as removed from tracking (soft delete)."""
        try:
            self.conn.execute(
                "UPDATE watchlist SET status='REMOVED' WHERE actor_id=?", (actor_id,)
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()

    def pause(self, actor_id: str) -> None:
        """Pause automatic re-scanning for an actor."""
        try:
            self.conn.execute(
                "UPDATE watchlist SET status='PAUSED' WHERE actor_id=?", (actor_id,)
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()

    def resume(self, actor_id: str) -> None:
        """Resume automatic re-scanning for an actor and recalculate its next scan time."""
        entry = self.get(actor_id)
        interval = entry.interval_hours if entry else 6
        next_scan = (
            datetime.now(timezone.utc) + timedelta(hours=interval)
        ).isoformat()

        try:
            self.conn.execute(
                "UPDATE watchlist SET status='ACTIVE', next_scan=? WHERE actor_id=?",
                (next_scan, actor_id),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()

    def get(self, actor_id: str) -> WatchlistEntry | None:
        """Fetch a single watchlist entry by actor_id, or None if not found."""
        try:
            row = self.conn.execute(
                "SELECT * FROM watchlist WHERE actor_id=?", (actor_id,)
            ).fetchone()
        except Exception:
            return None

        return self._row_to_entry(row) if row else None

    def all_active(self) -> list[WatchlistEntry]:
        """Return all entries currently in ACTIVE status."""
        try:
            rows = self.conn.execute(
                "SELECT * FROM watchlist WHERE status='ACTIVE'"
            ).fetchall()
        except Exception:
            return []
        return [self._row_to_entry(r) for r in rows]

    def due_for_scan(self) -> list[WatchlistEntry]:
        """Return all ACTIVE entries whose next_scan time has passed."""
        try:
            rows = self.conn.execute(
                "SELECT * FROM watchlist WHERE status='ACTIVE' AND next_scan <= ?",
                (datetime.now(timezone.utc).isoformat(),),
            ).fetchall()
        except Exception:
            return []
        return [self._row_to_entry(r) for r in rows]

    def update_scan_time(self, actor_id: str) -> None:
        """Update last_scanned/next_scan/scan_count after a scan completes."""
        entry = self.get(actor_id)
        if not entry:
            return

        now = datetime.now(timezone.utc)
        next_scan = now + timedelta(hours=entry.interval_hours)

        try:
            self.conn.execute(
                """
                UPDATE watchlist
                SET last_scanned=?, next_scan=?, scan_count=scan_count+1
                WHERE actor_id=?
                """,
                (now.isoformat(), next_scan.isoformat(), actor_id),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()

    def get_stats(self) -> dict:
        """Return aggregate counts of tracked actors by status."""
        try:
            total = self.conn.execute("SELECT COUNT(*) c FROM watchlist").fetchone()["c"]
            active = self.conn.execute(
                "SELECT COUNT(*) c FROM watchlist WHERE status='ACTIVE'"
            ).fetchone()["c"]
            paused = self.conn.execute(
                "SELECT COUNT(*) c FROM watchlist WHERE status='PAUSED'"
            ).fetchone()["c"]
            due = len(self.due_for_scan())
        except Exception:
            return {"total": 0, "active": 0, "paused": 0, "due": 0}

        return {"total": total, "active": active, "paused": paused, "due": due}

    def _row_to_entry(self, row: sqlite3.Row) -> WatchlistEntry:
        """Convert a sqlite3.Row into a WatchlistEntry, decoding the identifiers JSON."""
        try:
            identifiers = json.loads(row["identifiers"] or "[]")
        except Exception:
            identifiers = []

        return WatchlistEntry(
            actor_id=row["actor_id"],
            handle=row["handle"],
            identifiers=identifiers,
            interval_hours=row["interval_hours"],
            status=row["status"],
            added_at=row["added_at"],
            last_scanned=row["last_scanned"],
            next_scan=row["next_scan"],
            notes=row["notes"] or "",
            scan_count=row["scan_count"] or 0,
        )
