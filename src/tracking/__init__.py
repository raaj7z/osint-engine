
from .watchlist import WatchlistEntry, WatchlistStore
from .change_detector import (
    HIGH_CONFIDENCE_THRESHOLD,
    build_change_events,
    compare_findings,
    detect_changes,
    summarize_changes,
)
from .alert_manager import AlertManager
from .scheduler import Scheduler, WatchlistScheduler


class TrackingManager:
    def __init__(
        self,
        db=None,
        scan_callback=None,
        tick_seconds=15,
    ):
        self.db = db

        self.watchlist = WatchlistStore(
            db=db,
        )

        self.alerts = AlertManager(
            db=db,
        )

        self.scheduler = None

        if scan_callback is not None:
            self.scheduler = WatchlistScheduler(
                watchlist_store=self.watchlist,
                callback=scan_callback,
                alert_manager=self.alerts,
                tick_seconds=tick_seconds,
            )

    def add_actor(
        self,
        actor_id,
        interval_minutes=360,
    ):
        return self.watchlist.add(
            actor_id=actor_id,
            interval_minutes=interval_minutes,
        )

    def remove_actor(
        self,
        watch_id,
    ):
        self.watchlist.remove(
            watch_id,
        )

    def pause_actor(
        self,
        watch_id,
    ):
        self.watchlist.pause(
            watch_id,
        )

    def resume_actor(
        self,
        watch_id,
    ):
        self.watchlist.resume(
            watch_id,
        )

    def compare(
        self,
        previous_findings,
        current_findings,
    ):
        return compare_findings(
            previous_findings,
            current_findings,
        )

    def process(
        self,
        previous_findings,
        current_findings,
        actor_id=None,
        investigation_id=None,
        run_id=None,
    ):
        changes = compare_findings(
            previous_findings,
            current_findings,
        )

        alert_ids = self.alerts.create_from_changes(
            changes=changes,
            actor_id=actor_id,
            investigation_id=investigation_id,
            run_id=run_id,
        )

        return {
            "actor_id": actor_id,
            "investigation_id": investigation_id,
            "run_id": run_id,
            "changes": changes,
            "summary": summarize_changes(
                changes,
            ),
            "events": build_change_events(
                changes,
            ),
            "alert_ids": alert_ids,
            "checked_at": changes.get(
                "checked_at",
            ),
        }

    def start(self):
        if self.scheduler is None:
            return False

        return self.scheduler.start()

    def stop(self):
        if self.scheduler is None:
            return True

        return self.scheduler.stop()

    def status(self):
        scheduler_status = {
            "running": False,
        }

        if self.scheduler is not None:
            scheduler_status = self.scheduler.status()

        return {
            "watchlist": self.watchlist.stats(),
            "unread_alerts": self.alerts.count_unread(),
            "scheduler": scheduler_status,
        }


__all__ = [
    "WatchlistEntry",
    "WatchlistStore",
    "AlertManager",
    "WatchlistScheduler",
    "Scheduler",
    "TrackingManager",
    "HIGH_CONFIDENCE_THRESHOLD",
    "compare_findings",
    "detect_changes",
    "build_change_events",
    "summarize_changes",
]
