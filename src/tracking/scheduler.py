from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Callable


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class WatchlistScheduler:
    def __init__(
        self,
        watchlist_store: Any,
        callback: Callable[[dict[str, Any]], Any],
        alert_manager: Any = None,
        tick_seconds: int = 15,
    ):
        self.watchlist_store = watchlist_store
        self.callback = callback
        self.alert_manager = alert_manager
        self.tick_seconds = max(1, int(tick_seconds))

        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()

        self.running_state = False
        self.last_tick_at: str | None = None
        self.last_error: str | None = None
        self.last_results: list[dict[str, Any]] = []

    def start(self) -> bool:
        with self.lock:
            if self.thread and self.thread.is_alive():
                return False

            self.stop_event.clear()
            self.running_state = True
            self.last_error = None

            self.thread = threading.Thread(
                target=self._loop,
                name="pralayx-watchlist-scheduler",
                daemon=True,
            )

            self.thread.start()
            return True

    def stop(self, timeout: float = 5.0) -> bool:
        self.stop_event.set()

        thread = self.thread

        if (
            thread
            and thread.is_alive()
            and thread is not threading.current_thread()
        ):
            thread.join(
                timeout=max(
                    0.1,
                    float(timeout),
                )
            )

        self.running_state = False

        return not (
            thread
            and thread.is_alive()
        )

    def running(self) -> bool:
        return bool(
            self.thread
            and self.thread.is_alive()
            and self.running_state
        )

    def tick(self) -> list[dict[str, Any]]:
        self.last_tick_at = utc_now()

        processed: list[dict[str, Any]] = []

        try:
            due_entries = self.watchlist_store.due()
        except Exception as exc:
            self.last_error = str(exc)
            return []

        for entry in due_entries:
            processed.append(
                self._process(entry)
            )

        self.last_results = processed

        return processed

    def _process(
        self,
        entry: dict[str, Any],
    ) -> dict[str, Any]:
        watch_id = entry.get("watch_id")
        actor_id = entry.get("actor_id")

        result: dict[str, Any] = {
            "watch_id": watch_id,
            "actor_id": actor_id,
            "started_at": utc_now(),
            "status": "RUNNING",
        }

        try:
            value = self.callback(entry)

            result["status"] = "COMPLETED"
            result["result"] = value

            if watch_id:
                try:
                    self.watchlist_store.mark_scanned(
                        watch_id
                    )
                except Exception:
                    pass

        except Exception as exc:
            error = str(exc)

            result["status"] = "ERROR"
            result["error"] = error
            self.last_error = error

            if self.alert_manager is not None:
                try:
                    self.alert_manager.create_monitoring_error(
                        actor_id=actor_id,
                        message=(
                            f"Scheduled monitoring failed "
                            f"for actor {actor_id}: {error}"
                        ),
                    )
                except Exception:
                    pass

        result["finished_at"] = utc_now()

        return result

    def _loop(self) -> None:
        while not self.stop_event.wait(
            self.tick_seconds
        ):
            try:
                self.tick()
            except Exception as exc:
                self.last_error = str(exc)

        self.running_state = False

    def status(self) -> dict[str, Any]:
        return {
            "running": self.running(),
            "tick_seconds": self.tick_seconds,
            "last_tick_at": self.last_tick_at,
            "last_error": self.last_error,
            "last_results": self.last_results,
        }


class ScanScheduler:
    """
    Compatibility wrapper used by the interactive OSINT CLI.

    It keeps the CLI-facing constructor compatible while using
    the same watchlist scheduler implementation underneath.
    """

    def __init__(
        self,
        engine: Any,
        watchlist_store: Any,
        alert_manager: Any = None,
        change_detector: Any = None,
        tick_seconds: int = 15,
    ):
        self.engine = engine
        self.watchlist_store = watchlist_store
        self.alert_manager = alert_manager
        self.change_detector = change_detector

        callback = self._scan_entry

        self.scheduler = WatchlistScheduler(
            watchlist_store=watchlist_store,
            callback=callback,
            alert_manager=alert_manager,
            tick_seconds=tick_seconds,
        )

    def _scan_entry(
        self,
        entry: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Execute a scheduled actor scan when the entry contains
        usable identifiers. Otherwise return a controlled status.
        """

        actor_id = entry.get("actor_id")

        identifiers = (
            entry.get("identifiers")
            or []
        )

        if not identifiers:
            return {
                "actor_id": actor_id,
                "status": "NO_RESULTS",
                "message": (
                    "No identifiers available "
                    "for scheduled scan."
                ),
            }

        try:
            from ..models import (
                Identifier,
                InvestigationInput,
            )

            normalized = []

            for item in identifiers:
                if isinstance(item, Identifier):
                    normalized.append(item)
                    continue

                if not isinstance(item, dict):
                    continue

                value = (
                    item.get("value")
                    or item.get("identifier")
                )

                id_type = (
                    item.get("type")
                    or item.get("finding_type")
                    or "other"
                )

                if value:
                    normalized.append(
                        Identifier(
                            type=id_type,
                            value=str(value),
                            source=item.get(
                                "source",
                                "watchlist",
                            ),
                            source_url=item.get(
                                "source_url"
                            ),
                            confidence=float(
                                item.get(
                                    "confidence",
                                    1.0,
                                )
                            ),
                            metadata=item.get(
                                "metadata",
                                {},
                            ),
                        )
                    )

            if not normalized:
                return {
                    "actor_id": actor_id,
                    "status": "NO_RESULTS",
                    "message": (
                        "No valid identifiers "
                        "available for scheduled scan."
                    ),
                }

            investigation_id = (
                entry.get("investigation_id")
                or f"MON-{actor_id or 'UNKNOWN'}-"
                f"{int(datetime.now(timezone.utc).timestamp())}"
            )

            run_id = (
                entry.get("run_id")
                or f"RUN-{int(datetime.now(timezone.utc).timestamp())}"
            )

            investigation = InvestigationInput(
                investigation_id=investigation_id,
                actor_id=actor_id,
                run_id=run_id,
                identifiers=normalized,
                metadata={
                    "trigger": "scheduled_monitoring",
                    "watch_id": entry.get(
                        "watch_id"
                    ),
                },
            )

            result = self.engine.run(
                investigation
            )

            return {
                "actor_id": actor_id,
                "investigation_id": investigation_id,
                "run_id": run_id,
                "status": getattr(
                    result,
                    "status",
                    "COMPLETED",
                ),
                "findings": len(
                    getattr(
                        result,
                        "findings",
                        [],
                    )
                ),
            }

        except Exception as exc:
            return {
                "actor_id": actor_id,
                "status": "ERROR",
                "error": str(exc),
            }

    def start(self) -> bool:
        return self.scheduler.start()

    def stop(
        self,
        timeout: float = 5.0,
    ) -> bool:
        return self.scheduler.stop(
            timeout=timeout
        )

    def running(self) -> bool:
        return self.scheduler.running()

    def tick(self) -> list[dict[str, Any]]:
        return self.scheduler.tick()

    def status(self) -> dict[str, Any]:
        return self.scheduler.status()


Scheduler = WatchlistScheduler


__all__ = [
    "WatchlistScheduler",
    "ScanScheduler",
    "Scheduler",
]
