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
    """SQLite database adapter for the OSINT engine."""

    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or os.getenv(
            "OSINT_DB_PATH",
            "data/crawler.db",
        )

        os.makedirs(
            os.path.dirname(
                os.path.abspath(self.db_path)
            ),
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

        self._create_osint_tables()

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

    def _create_osint_tables(self) -> None:
        """Create OSINT-specific tables."""

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

    def migrate(self, schema_path: str) -> None:
        """Execute an external SQL schema file."""

        with open(
            schema_path,
            "r",
            encoding="utf-8",
        ) as file:
            self.conn.executescript(file.read())

        self.conn.commit()

    def create_investigation(
        self,
        target: str,
        target_type: str,
        source: str = "manual",
        notes: str | None = None,
        actor_id: str | None = None,
    ):
        investigation_id = str(uuid.uuid4())

        actor_id = actor_id or (
            f"actor-{uuid.uuid4().hex[:12]}"
        )

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

    def ensure_actor_for_investigation(
        self,
        investigation_id: str,
        display_name: str | None = None,
    ) -> str:

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

    def get_identifiers_from_crawler(
        self,
        investigation_id: str,
    ):
        identifiers = []

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
                            evidence,
                            "title",
                            None,
                        ),
                        getattr(
                            evidence,
                            "excerpt",
                            None,
                        ),
                        getattr(
                            evidence,
                            "hash_sha256",
                            None,
                        ),
                        getattr(
                            evidence,
                            "collected_at",
                            None,
                        ),
                        self._json(
                            getattr(
                                evidence,
                                "metadata",
                                None,
                            )
                            or {}
                        ),
                    ),
                )

        try:
            self.conn.execute(
                """
                UPDATE investigations
                SET
                    status = 'completed',
                    results = ?,
                    confidence_score = ?,
                    completed_at = ?
                WHERE session_id = ?
                """,
                (
                    self._json(
                        {
                            "errors": result.errors,
                            "finding_count": len(
                                result.findings
                            ),
                        }
                    ),
                    max(
                        (
                            finding.confidence
                            for finding in result.findings
                        ),
                        default=0.0,
                    ),
                    (
                        result.completed_at.isoformat()
                        if result.completed_at
                        else self._now()
                    ),
                    investigation_id,
                ),
            )

        except sqlite3.OperationalError:
            pass

        try:
            self.conn.execute(
                """
                UPDATE sessions
                SET
                    status = 'completed',
                    completed_at = ?
                WHERE session_id = ?
                """,
                (
                    result.completed_at.isoformat()
                    if result.completed_at
                    else self._now(),
                    investigation_id,
                ),
            )

        except sqlite3.OperationalError:
            pass

        self.conn.commit()

    def list_investigations(
        self,
        limit: int = 50,
    ):
        try:
            rows = self.conn.execute(
                """
                SELECT
                    session_id AS investigation_id,
                    target_username AS target,
                    status,
                    started_at,
                    completed_at,
                    confidence_score
                FROM investigations
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

            return [
                dict(row)
                for row in rows
            ]

        except sqlite3.OperationalError:
            return []

    def get_investigation(
        self,
        investigation_id: str,
    ):
        try:
            row = self.conn.execute(
                """
                SELECT *
                FROM investigations
                WHERE session_id = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (investigation_id,),
            ).fetchone()

        except sqlite3.OperationalError:
            row = None

        if not row:
            return None

        data = dict(row)

        data["findings"] = [
            dict(item)
            for item in self.conn.execute(
                """
                SELECT *
                FROM osint_findings
                WHERE investigation_id = ?
                ORDER BY created_at
                """,
                (investigation_id,),
            ).fetchall()
        ]

        data["identifiers"] = [
            dict(item)
            for item in self.conn.execute(
                """
                SELECT *
                FROM osint_identifiers
                WHERE investigation_id = ?
                ORDER BY created_at
                """,
                (investigation_id,),
            ).fetchall()
        ]

        return data

    def create_job(
        self,
        investigation_id: str,
        job_type: str,
    ) -> str:
        job_id = str(uuid.uuid4())

        self.conn.execute(
            """
            INSERT INTO osint_jobs
            (
                id,
                investigation_id,
                job_type,
                status
            )
            VALUES (?, ?, ?, 'queued')
            """,
            (
                job_id,
                investigation_id,
                job_type,
            ),
        )

        self.conn.commit()

        return job_id

    def update_job(
        self,
        job_id: str,
        status: str,
        progress: float | None = None,
        error: str | None = None,
    ) -> None:
        now = self._now()

        self.conn.execute(
            """
            UPDATE osint_jobs
            SET
                status = ?,
                progress = COALESCE(?, progress),
                error = ?,
                started_at =
                    CASE
                        WHEN ?
                             = 'running'
                             AND started_at IS NULL
                        THEN ?
                        ELSE started_at
                    END,
                completed_at =
                    CASE
                        WHEN ?
                             IN ('completed', 'failed')
                        THEN ?
                        ELSE completed_at
                    END
            WHERE id = ?
            """,
            (
                status,
                progress,
                error,
                status,
                now,
                status,
                now,
                job_id,
            ),
        )

        self.conn.commit()

    def add_job_event(
        self,
        job_id: str,
        investigation_id: str,
        event_type: str,
        message: str,
        level: str = "info",
        metadata: dict | None = None,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO osint_job_events
            (
                job_id,
                investigation_id,
                level,
                event_type,
                message,
                metadata
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                job_id,
                investigation_id,
                level,
                event_type,
                message,
                self._json(
                    metadata or {}
                ),
            ),
        )

        self.conn.commit()

    def get_job(
        self,
        job_id: str,
    ):
        row = self.conn.execute(
            """
            SELECT *
            FROM osint_jobs
            WHERE id = ?
            """,
            (job_id,),
        ).fetchone()

        return dict(row) if row else None

    def get_job_events(
        self,
        job_id: str,
        after_id: int = 0,
    ):
        rows = self.conn.execute(
            """
            SELECT *
            FROM osint_job_events
            WHERE job_id = ?
              AND id > ?
            ORDER BY id
            """,
            (
                job_id,
                after_id,
            ),
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    def get_previous_findings(
        self,
        actor_id: str,
    ):
        rows = self.conn.execute(
            """
            SELECT *
            FROM osint_findings
            WHERE actor_id = ?
            ORDER BY created_at
            """,
            (actor_id,),
        ).fetchall()

        result = []

        for row in rows:
            item = dict(row)

            metadata = item.get("metadata")

            if metadata:
                try:
                    item["metadata"] = json.loads(
                        metadata
                    )

                except (
                    TypeError,
                    json.JSONDecodeError,
                ):
                    item["metadata"] = {}

            item.pop("id", None)

            result.append(item)

        return result

    def export_csv(
        self,
        actor_id: str,
        output_path: str,
    ) -> str:
        rows = self.conn.execute(
            """
            SELECT
                investigation_id,
                actor_id,
                finding_type,
                value,
                source,
                source_url,
                confidence,
                first_seen,
                last_seen,
                metadata,
                created_at
            FROM osint_findings
            WHERE actor_id = ?
            ORDER BY created_at
            """,
            (actor_id,),
        ).fetchall()

        os.makedirs(
            os.path.dirname(
                os.path.abspath(output_path)
            ),
            exist_ok=True,
        )

        fieldnames = [
            "investigation_id",
            "actor_id",
            "finding_type",
            "value",
            "source",
            "source_url",
            "confidence",
            "first_seen",
            "last_seen",
            "metadata",
            "created_at",
        ]

        with open(
            output_path,
            "w",
            newline="",
            encoding="utf-8",
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=fieldnames,
            )

            writer.writeheader()

            for row in rows:
                writer.writerow(
                    dict(row)
                )

        return output_path

    def get_stats(self):
        def count(table: str) -> int:
            return self.conn.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]

        return {
            "actors": count("osint_actors"),
            "identifiers": count("osint_identifiers"),
            "findings": count("osint_findings"),
            "evidence": count("osint_evidence"),
            "jobs": count("osint_jobs"),
        }
