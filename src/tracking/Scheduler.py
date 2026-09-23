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
        callback: Callable[
            [dict[str, Any]],
            Any,
        ],
        alert_manager: Any = None,
        tick_seconds: int = 15,
    ):
        self.watchlist_store = watchlist_store
        self.callback = callback
        self.alert_manager = alert_manager
        self.tick_seconds = max(
            1,
            int(tick_seconds),
        )

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

    def stop(
        self,
        timeout: float = 5.0,
    ) -> bool:
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
            result = self._process(entry)
            processed.append(result)

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
                        watch_id,
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


Scheduler = WatchlistScheduler


__all__ = [
    "WatchlistScheduler",
    "Scheduler",
]
