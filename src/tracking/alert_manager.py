from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AlertManager:
    def __init__(self, db: Any = None):
        self.db = db

    def create(
        self,
        actor_id: str | None,
        alert_type: str,
        message: str,
        finding_id: str | None = None,
        confidence: float | None = None,
        severity: str = "MEDIUM",
        investigation_id: str | None = None,
        run_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str | None:
        if self.db is None:
            return None

        payload = {
            "severity": severity,
            "investigation_id": investigation_id,
            "run_id": run_id,
            "metadata": metadata or {},
        }

        try:
            alert_id = self.db.add_alert(
                actor_id=actor_id,
                finding_id=finding_id,
                alert_type=alert_type,
                message=message,
                confidence=confidence,
            )
        except Exception:
            return None

        if investigation_id:
            try:
                self.db.add_timeline_event(
                    investigation_id=investigation_id,
                    event_type="alert_created",
                    message=message,
                    actor_id=actor_id,
                    run_id=run_id,
                    payload={
                        "alert_id": alert_id,
                        "alert_type": alert_type,
                        **payload,
                    },
                )
            except Exception:
                pass

        return alert_id

    def create_from_event(
        self,
        event: dict[str, Any],
        actor_id: str | None = None,
        investigation_id: str | None = None,
        run_id: str | None = None,
    ) -> str | None:
        finding = event.get("finding") or {}

        confidence = finding.get("confidence")

        try:
            confidence = (
                float(confidence)
                if confidence is not None
                else None
            )
        except (TypeError, ValueError):
            confidence = None

        return self.create(
            actor_id=actor_id,
            alert_type=str(
                event.get(
                    "event_type",
                    "monitoring_alert",
                )
            ),
            message=str(
                event.get(
                    "message",
                    "Monitoring event detected",
                )
            ),
            finding_id=finding.get("finding_id"),
            confidence=confidence,
            severity=str(
                event.get(
                    "severity",
                    "MEDIUM",
                )
            ),
            investigation_id=investigation_id,
            run_id=run_id,
            metadata={
                "finding": finding,
                "before": event.get("before"),
            },
        )

    def create_from_changes(
        self,
        changes: dict[str, Any],
        actor_id: str | None = None,
        investigation_id: str | None = None,
        run_id: str | None = None,
    ) -> list[str]:
        from .change_detector import build_change_events

        alert_ids: list[str] = []

        for event in build_change_events(changes):
            alert_id = self.create_from_event(
                event,
                actor_id=actor_id,
                investigation_id=investigation_id,
                run_id=run_id,
            )

            if alert_id:
                alert_ids.append(alert_id)

        return alert_ids

    def create_monitoring_error(
        self,
        actor_id: str | None,
        message: str,
        investigation_id: str | None = None,
        run_id: str | None = None,
    ) -> str | None:
        return self.create(
            actor_id=actor_id,
            alert_type="monitoring_error",
            message=message,
            severity="HIGH",
            investigation_id=investigation_id,
            run_id=run_id,
        )

    def list(
        self,
        actor_id: str | None = None,
    ) -> list[dict[str, Any]]:
        if self.db is None:
            return []

        try:
            if actor_id:
                return self.db.list_alerts(
                    actor_id=actor_id,
                )

            return self.db.list_alerts()
        except Exception:
            return []

    def acknowledge(
        self,
        alert_id: str,
    ) -> bool:
        if self.db is None:
            return False

        try:
            self.db.execute(
                """
                UPDATE sih_alerts
                SET acknowledged = 1,
                    acknowledged_at = ?
                WHERE alert_id = ?
                """,
                (
                    utc_now(),
                    alert_id,
                ),
            )
            return True
        except Exception:
            try:
                self.db.conn.rollback()
            except Exception:
                pass
            return False

    def unacknowledge(
        self,
        alert_id: str,
    ) -> bool:
        if self.db is None:
            return False

        try:
            self.db.execute(
                """
                UPDATE sih_alerts
                SET acknowledged = 0,
                    acknowledged_at = NULL
                WHERE alert_id = ?
                """,
                (alert_id,),
            )
            return True
        except Exception:
            try:
                self.db.conn.rollback()
            except Exception:
                pass
            return False

    def unread(
        self,
        actor_id: str | None = None,
    ) -> list[dict[str, Any]]:
        alerts = self.list(actor_id)

        return [
            alert
            for alert in alerts
            if not alert.get("acknowledged")
        ]

    def count_unread(
        self,
        actor_id: str | None = None,
    ) -> int:
        return len(
            self.unread(actor_id)
        )


__all__ = [
    "AlertManager",
]
