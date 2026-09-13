from __future__ import annotations

import csv
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

from .models import Identifier, InvestigationResult


class OSINTDatabase:
    """Additive SQLite adapter for the OSINT engine."""

    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or os.getenv(
            "OSINT_DB_PATH",
            "data/crawler.db",
        )

        os.makedirs(
            os.path.dirname(os.path.abspath(self.db_path)),
            exist_ok=True,
        )

        self.conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=30,
        )

        self.conn.row_factory = sqlite3.Row

        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=30000")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA foreign_keys=ON")

        # Create OSINT tables automatically.
        self._create_osint_tables()

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(
            value,
            ensure_ascii=False,
            default=str,
        )

    def close(self) -> None:
        self.conn.close()

    # ------------------------------------------------------------------
    # OSINT schema
    # ------------------------------------------------------------------

    def _create_osint_tables(self) -> None:
        """Create OSINT-specific tables without modifying crawler tables."""

        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS osint_actors (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                display_name TEXT,
                category TEXT DEFAULT 'unknown',
                confidence_level TEXT DEFAULT 'insufficient',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS osint_identifiers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id TEXT NOT NULL,
                actor_id TEXT,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                normalized_value TEXT,
                source TEXT DEFAULT 'manual',
                source_url TEXT,
                confidence REAL DEFAULT 0.5,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS osint_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id TEXT NOT NULL,
                actor_id TEXT,
                finding_type TEXT,
                value TEXT,
                normalized_value TEXT,
                source TEXT,
                source_url TEXT,
                confidence REAL DEFAULT 0.0,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS osint_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id TEXT NOT NULL,
                finding_id INTEGER,
                source_url TEXT,
                title TEXT,
                excerpt TEXT,
                content_hash TEXT,
                collected_at TIMESTAMP,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS osint_jobs (
                id TEXT PRIMARY KEY,
                investigation_id TEXT,
                job_type TEXT NOT NULL,
                status TEXT DEFAULT 'queued',
                progress REAL DEFAULT 0.0,
                error TEXT,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS osint_job_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                investigation_id TEXT,
                level TEXT DEFAULT 'info',
                event_type TEXT,
                message TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_osint_actors_investigation
                ON osint_actors(investigation_id);

            CREATE INDEX IF NOT EXISTS idx_osint_identifiers_investigation
                ON osint_identifiers(investigation_id);

            CREATE INDEX IF NOT EXISTS idx_osint_findings_investigation
                ON osint_findings(investigation_id);

            CREATE INDEX IF NOT EXISTS idx_osint_findings_actor
                ON osint_findings(actor_id);

            CREATE INDEX IF NOT EXISTS idx_osint_evidence_finding
                ON osint_evidence(finding_id);

            CREATE INDEX IF NOT EXISTS idx_osint_jobs_investigation
                ON osint_jobs(investigation_id);

            CREATE INDEX IF NOT EXISTS idx_osint_job_events_job
                ON osint_job_events(job_id);
            """
        )

        self.conn.commit()

    # ------------------------------------------------------------------
    # Schema migration
    # ------------------------------------------------------------------

    def migrate(self, schema_path: str) -> None:
        """Run an external SQL schema file."""

        with open(
            schema_path,
            "r",
            encoding="utf-8",
        ) as file:
            self.conn.executescript(file.read())

        self.conn.commit()

    # ------------------------------------------------------------------
    # Investigation
    # ------------------------------------------------------------------

    def create_investigation(
        self,
        target: str,
        target_type: str,
        source: str = "manual",
        notes: str | None = None,
        actor_id: str | None = None,
    ):
        """Create an investigation and its initial actor."""

        investigation_id = str(uuid.uuid4())

        actor_id = actor_id or (
            f"actor-{uuid.uuid4().hex[:12]}"
        )

        # These are crawler-compatible tables.
        # CREATE IF NOT EXISTS prevents errors on a fresh OSINT database.
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE,
                target_username TEXT,
                urls_crawled TEXT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                status TEXT DEFAULT 'running',
                summary TEXT
            )
            """
        )

        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                target_username TEXT,
                status TEXT DEFAULT 'running',
                results TEXT,
                confidence_score REAL,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            )
            """
        )

        self.conn.execute(
            """
            INSERT OR IGNORE INTO sessions
            (
                session_id,
                target_username,
                urls_crawled,
                status
            )
            VALUES (?, ?, ?, 'running')
            """,
            (
                investigation_id,
                target,
                self._json([target])
                if target_type == "url"
                else "[]",
            ),
        )

        self.conn.execute(
            """
            INSERT INTO investigations
            (
                session_id,
                target_username,
                status,
                results
            )
            VALUES (?, ?, 'running', ?)
            """,
            (
                investigation_id,
                target,
                self._json(
                    {
                        "source": source,
                        "target_type": target_type,
                        "notes": notes,
                    }
                ),
            ),
        )

        self.conn.execute(
            """
            INSERT INTO osint_actors
            (
                id,
                investigation_id,
                display_name,
                category,
                confidence_level
            )
            VALUES (?, ?, ?, 'unknown', 'insufficient')
            """,
            (
                actor_id,
                investigation_id,
                target,
            ),
        )

        self.conn.execute(
            """
            INSERT INTO osint_identifiers
            (
                investigation_id,
                actor_id,
                type,
                value,
                normalized_value,
                source
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                investigation_id,
                actor_id,
                target_type,
                target,
                target.strip().lower(),
                source,
            ),
        )

        self.conn.commit()

        return investigation_id, actor_id

    # ------------------------------------------------------------------
    # Actor
    # ------------------------------------------------------------------

    def ensure_actor_for_investigation(
        self,
        investigation_id: str,
        display_name: str | None = None,
    ) -> str:
        """Return an existing actor or create one."""

        row = self.conn.execute(
            """
            SELECT id
            FROM osint_actors
            WHERE investigation_id = ?
            ORDER BY created_at
            LIMIT 1
            """,
            (investigation_id,),
        ).fetchone()

        if row:
            return row["id"]

        actor_id = (
            f"actor-{uuid.uuid4().hex[:12]}"
        )

        self.conn.execute(
            """
            INSERT INTO osint_actors
            (
                id,
                investigation_id,
                display_name,
                category,
                confidence_level
            )
            VALUES (?, ?, ?, 'unknown', 'insufficient')
            """,
            (
                actor_id,
                investigation_id,
                display_name,
            ),
        )

        self.conn.commit()

        return actor_id

    # ------------------------------------------------------------------
    # Crawler investigation
    # ------------------------------------------------------------------

    def get_crawler_investigation(
        self,
        crawler_investigation_id: int,
    ):
        row = self.conn.execute(
            """
            SELECT *
            FROM investigations
            WHERE id = ?
            """,
            (crawler_investigation_id,),
        ).fetchone()

        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Crawler identifiers
    # ------------------------------------------------------------------

    def get_identifiers_from_crawler(
        self,
        investigation_id: str,
    ):
        """Extract identifiers from crawler output."""

        identifiers = []

        # Username from crawler session.
        try:
            row = self.conn.execute(
                """
                SELECT target_username
                FROM sessions
                WHERE session_id = ?
                """,
                (investigation_id,),
            ).fetchone()

            if row and row["target_username"]:
                identifiers.append(
                    Identifier(
                        type="username",
                        value=row["target_username"],
                        source="crawler",
                    )
                )

        except sqlite3.OperationalError:
            pass

        # Usernames.
        try:
            rows = self.conn.execute(
                """
                SELECT username, source_url
                FROM usernames
                WHERE session_id = ?
                """,
                (investigation_id,),
            ).fetchall()

            for row in rows:
                if row["username"]:
                    identifiers.append(
                        Identifier(
                            type="username",
                            value=row["username"],
                            source="crawler",
                            source_url=row["source_url"],
                        )
                    )

        except sqlite3.OperationalError:
            pass

        # Crypto addresses.
        try:
            rows = self.conn.execute(
                """
                SELECT address, source_url
                FROM crypto_addresses
                WHERE session_id = ?
                """,
                (investigation_id,),
            ).fetchall()

            for row in rows:
                if row["address"]:
                    identifiers.append(
                        Identifier(
                            type="crypto",
                            value=row["address"],
                            source="crawler",
                            source_url=row["source_url"],
                        )
                    )

        except sqlite3.OperationalError:
            pass

        # Links.
        try:
            rows = self.conn.execute(
                """
                SELECT target_url, source_url
                FROM links
                WHERE session_id = ?
                """,
                (investigation_id,),
            ).fetchall()

            for row in rows:
                target_url = row["target_url"]

                if not target_url:
                    continue

                identifier_type = (
                    "url"
                    if "://" in target_url
                    else "domain"
                )

                identifiers.append(
                    Identifier(
                        type=identifier_type,
                        value=target_url,
                        source="crawler",
                        source_url=row["source_url"],
                    )
                )

        except sqlite3.OperationalError:
            pass

        # Remove duplicates.
        seen = set()
        result = []

        for identifier in identifiers:
            key = (
                identifier.type,
                identifier.value.strip().lower(),
            )

            if key not in seen:
                seen.add(key)
                result.append(identifier)

        return result

    # ------------------------------------------------------------------
    # Identifier registration
    # ------------------------------------------------------------------

    def register_identifiers(
        self,
        investigation_id: str,
        actor_id: str | None,
        identifiers,
    ) -> None:

        for item in identifiers:
            self.conn.execute(
                """
                INSERT INTO osint_identifiers
                (
                    investigation_id,
                    actor_id,
                    type,
                    value,
                    normalized_value,
                    source,
                    source_url,
                    confidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    investigation_id,
                    actor_id,
                    item.type,
                    item.value,
                    item.value.strip().lower(),
                    getattr(
                        item,
                        "source",
                        "crawler",
                    ),
                    getattr(
                        item,
                        "source_url",
                        None,
                    ),
                    getattr(
                        item,
                        "confidence",
                        0.5,
                    ),
                ),
            )

        self.conn.commit()

    # ------------------------------------------------------------------
    # Save investigation results
    # ------------------------------------------------------------------

    def save_investigation(
        self,
        result: InvestigationResult,
    ) -> None:

        investigation_id = result.investigation_id

        actor_id = (
            result.actor_id
            or self.ensure_actor_for_investigation(
                investigation_id
            )
        )

        for finding in result.findings:

            cursor = self.conn.execute(
                """
                INSERT INTO osint_findings
                (
                    investigation_id,
                    actor_id,
                    finding_type,
                    value,
                    normalized_value,
                    source,
                    source_url,
                    confidence,
                    first_seen,
                    last_seen,
                    metadata
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    investigation_id,
                    actor_id,
                    finding.finding_type,
                    finding.value,
                    finding.value.strip().lower(),
                    finding.source,
                    finding.source_url,
                    finding.confidence,
                    getattr(
                        finding,
                        "first_seen",
                        None,
                    ),
                    getattr(
                        finding,
                        "last_seen",
                        None,
                    ),
                    self._json(
                        getattr(
                            finding,
                            "metadata",
                            None,
                        )
                        or {}
                    ),
                ),
            )

            finding_id = cursor.lastrowid

            for evidence in (
                getattr(
                    finding,
                    "evidence",
                    [],
                )
                or []
            ):

                self.conn.execute(
                    """
                    INSERT INTO osint_evidence
                    (
                        investigation_id,
                        finding_id,
                        source_url,
                        title,
                        excerpt,
                        content_hash,
                        collected_at,
                        metadata
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        investigation_id,
                        finding_id,
                        getattr(
                            evidence,
                            "source_url",
                            None,
                        ),
                        getattr(
                            evidenc
