"""Alert management for the tracking subsystem.

Persists alerts to SQLite whenever a tracked actor's re-scan surfaces
a new, noteworthy finding.
"""

import os
import sqlite3
import uuid
from datetime import datetime, timezone

from ..models import Finding

try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init(autoreset=True)
    _COLOR = True
except ImportError:  # pragma: no cover - optional dependency
    _COLOR = False


class AlertManager:
    """SQLite-backed manager for tracking alerts."""

    def __init__(self, db_path: str = "data/alerts.db"):
        """Open (or create) the alerts database and ensure the table exists."""
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_table()

    def _create_table(self) -> None:
        """Create the alerts table if it doesn't already exist."""
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE,
                actor_id TEXT,
                handle TEXT,
                alert_type TEXT,
                finding_type TEXT,
                value TEXT,
                message TEXT,
                confidence REAL,
                is_read INTEGER DEFAULT 0,
                created_at TEXT
            )
            """
        )
        self.conn.commit()

    def _determine_alert_type(self, finding: Finding) -> str:
        """Classify a finding into an alert type based on its type/source/metadata."""
        if finding.finding_type in ("username", "forum_profile"):
            return "NEW_PLATFORM"
        if finding.finding_type == "crypto":
            return "NEW_WALLET"
        if "breach" in finding.source.lower() or "xposedornot" in finding.source.lower():
            return "BREACH_FOUND"
        if finding.metadata.get("is_tor_exit"):
            return "TOR_EXIT"
        if (finding.metadata.get("abuseConfidenceScore") or 0) > 50:
            return "HIGH_ABUSE"
        return "NEW_FINDING"

    def create_alert(self, actor_id: str, handle: str, finding: Finding) -> str:
        """Create, persist, and print an alert for a newly discovered finding."""
        alert_id = f"ALT-{uuid.uuid4().hex[:6].upper()}"
        alert_type = self._determine_alert_type(finding)
        message = f"[{alert_type}] {handle}: {finding.value} found on {finding.source}"

        try:
            self.conn.execute(
                """
                INSERT INTO alerts
                (alert_id, actor_id, handle, alert_type, finding_type, value,
                 message, confidence, is_read, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    alert_id,
                    actor_id,
                    handle,
                    alert_type,
                    finding.finding_type,
                    finding.value,
                    message,
                    finding.confidence,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()

        self._print_alert(alert_type, message)
        return alert_id

    def _print_alert(self, alert_type: str, message: str) -> None:
        """Print a colorized alert line to the terminal (falls back to plain text)."""
        if _COLOR:
            color = (
                Fore.RED
                if alert_type in ("TOR_EXIT", "HIGH_ABUSE", "BREACH_FOUND")
                else Fore.YELLOW
            )
            print(f"{color}{message}{Style.RESET_ALL}")
        else:
            print(message)

    def get_unread(self) -> list[dict]:
        """Return all unread alerts, most recent first."""
        try:
            rows = self.conn.execute(
                "SELECT * FROM alerts WHERE is_read=0 ORDER BY created_at DESC"
            ).fetchall()
        except Exception:
            return []
        return [dict(r) for r in rows]

    def get_all(self, actor_id: str | None = None, limit: int = 50) -> list[dict]:
        """Return alerts, optionally filtered to a single actor, most recent first."""
        try:
            if actor_id:
                rows = self.conn.execute(
                    "SELECT * FROM alerts WHERE actor_id=? ORDER BY created_at DESC LIMIT ?",
                    (actor_id, limit),
                ).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        except Exception:
            return []
        return [dict(r) for r in rows]

    def mark_read(self, alert_id: str) -> None:
        """Mark a single alert as read."""
        try:
            self.conn.execute(
                "UPDATE alerts SET is_read=1 WHERE alert_id=?", (alert_id,)
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()

    def mark_all_read(self) -> None:
        """Mark all unread alerts as read."""
        try:
            self.conn.execute("UPDATE alerts SET is_read=1 WHERE is_read=0")
            self.conn.commit()
        except Exception:
            self.conn.rollback()

    def get_stats(self) -> dict:
        """Return total/unread counts and a breakdown of alerts by type."""
        try:
            total = self.conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
            unread = self.conn.execute(
                "SELECT COUNT(*) c FROM alerts WHERE is_read=0"
            ).fetchone()["c"]
            rows = self.conn.execute(
                "SELECT alert_type, COUNT(*) c FROM alerts GROUP BY alert_type"
            ).fetchall()
            by_type = {r["alert_type"]: r["c"] for r in rows}
        except Exception:
            return {"total": 0, "unread": 0, "by_type": {}}

        return {"total": total, "unread": unread, "by_type": by_type}
