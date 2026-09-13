"""Background scheduler for automatic re-scanning of watchlisted actors."""

import threading
import time
from datetime import datetime, timedelta, timezone

from ..models import Finding, Identifier, InvestigationInput
from .watchlist import WatchlistEntry


class ScanScheduler:
    """Runs in a background thread, periodically re-scanning actors due for a check."""

    def __init__(self, engine, watchlist_store, alert_manager, change_detector):
        """Wire up the scheduler with the engine and tracking components it depends on."""
        self.engine = engine
        self.store = watchlist_store
        self.alerts = alert_manager
        self.detector = change_detector
        self._running = False
        self._thread: threading.Thread | None = None
        self._check_interval_seconds = 300

    def start(self) -> None:
        """Start the background scheduling thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        print("Scheduler started — checking every 5 minutes")

    def stop(self) -> None:
        """Stop the background scheduling thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        print("Scheduler stopped")

    def _loop(self) -> None:
        """Main loop: check for due actors, scan them, then sleep."""
        while self._running:
            try:
                due = self.store.due_for_scan()
                for entry in due:
                    try:
                        self._scan_actor(entry)
                    except Exception:
                        continue
            except Exception:
                pass
            time.sleep(self._check_interval_seconds)

    def _get_previous_findings(self, actor_id: str) -> list[Finding]:
        """Fetch prior findings for an actor from the engine's database, if available."""
        db = getattr(self.engine, "db", None)
        if not db:
            return []
        try:
            raw = db.get_previous_findings(actor_id)
            return [
                Finding(**{k: v for k, v in r.items() if k in Finding.model_fields})
                for r in raw
            ]
        except Exception:
            return []

    def _scan_actor(self, entry: WatchlistEntry) -> None:
        """Re-scan a single watchlisted actor, detect changes, and raise alerts for new findings."""
        previous = self._get_previous_findings(entry.actor_id)

        identifiers = [
            Identifier(type=i["type"], value=i["value"]) for i in entry.identifiers
        ]

        investigation = InvestigationInput(
            investigation_id=f"SCHED-{entry.actor_id}-{int(time.time())}",
            actor_id=entry.actor_id,
            identifiers=identifiers,
        )

        result = self.engine.run(investigation)

        diffs = self.detector.detect(previous, result.findings)

        for finding in diffs["added"]:
            self.alerts.create_alert(entry.actor_id, entry.handle, finding)

        self.store.update_scan_time(entry.actor_id)

        db = getattr(self.engine, "db", None)
        if db:
            try:
                db.save_investigation(result)
            except Exception:
                pass

    def status(self) -> dict:
        """Return the scheduler's current running state and tracked-actor count."""
        next_check = (
            datetime.now(timezone.utc) + timedelta(seconds=self._check_interval_seconds)
        ).isoformat()
        try:
            tracked = len(self.store.all_active())
        except Exception:
            tracked = 0

        return {
            "running": self._running,
            "next_check": next_check,
            "tracked": tracked,
        }
