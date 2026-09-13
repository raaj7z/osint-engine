"""Interactive CLI and module entrypoint for the OSINT engine.

Usage:
    python -m src.engine --username handle --domain example.com
    python src/main.py   (interactive menu)
"""

import argparse
import sys
from datetime import datetime, timezone

from .ai_cleaner import AICleaner
from .database import OSINTDatabase
from .engine import OSINTEngine
from .models import Finding, Identifier, InvestigationInput, InvestigationResult
from .reports.opsec_scorer import OPSECScorer
from .reports.report_generator import ReportGenerator
from .tracking.alert_manager import AlertManager
from .tracking.change_detector import ChangeDetector
from .tracking.scheduler import ScanScheduler
from .tracking.watchlist import WatchlistEntry, WatchlistStore

try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init(autoreset=True)
    _COLOR = True
except ImportError:  # pragma: no cover - optional dependency
    _COLOR = False


def _c(text: str, color: str) -> str:
    """Colorize text if colorama is available, otherwise return it unchanged."""
    if not _COLOR:
        return text
    colors = {"green": Fore.GREEN, "yellow": Fore.YELLOW, "red": Fore.RED, "cyan": Fore.CYAN}
    return f"{colors.get(color, '')}{text}{Style.RESET_ALL}"


class OSINTCli:
    """Interactive command-line interface wrapping the OSINT engine and tracking system."""

    def __init__(self):
        """Wire up all engine, database, tracking, and reporting components."""
        self.db = OSINTDatabase()
        self.engine = OSINTEngine()
        # NOTE: assumes OSINTEngine allows attribute assignment; the scheduler
        # and report/export flows below use self.engine.db when present.
        self.engine.db = self.db
        self.watchlist = WatchlistStore()
        self.alerts = AlertManager()
        self.detector = ChangeDetector()
        self.scheduler = ScanScheduler(self.engine, self.watchlist, self.alerts, self.detector)
        self.cleaner = AICleaner()
        self.scorer = OPSECScorer()
        self.reporter = ReportGenerator(db=self.db, scorer=self.scorer)

    def run_menu(self) -> None:
        """Print the banner and run the interactive menu loop until exit."""
        print(_c("=" * 60, "cyan"))
        print(_c("  OSINT ENGINE — SIH26151 — Dark Web De-anonymization", "cyan"))
        print(_c("=" * 60, "cyan"))

        while True:
            self._print_menu()
            choice = input("\nSelect option: ").strip()

            if choice == "1":
                self._investigate_manual()
            elif choice == "2":
                self._investigate_from_crawler()
            elif choice == "3":
                self._view_watchlist()
            elif choice == "4":
                self._add_to_watchlist()
            elif choice == "5":
                self._remove_from_watchlist()
            elif choice == "6":
                self._pause_resume()
            elif choice == "7":
                self._view_unread_alerts()
            elif choice == "8":
                self._view_actor_alerts()
            elif choice == "9":
                self.scheduler.start()
            elif choice == "10":
                self.scheduler.stop()
            elif choice == "11":
                self._generate_report()
            elif choice == "12":
                self._export_csv()
            elif choice == "13":
                self._view_stats()
            elif choice == "14":
                print("Goodbye.")
                sys.exit(0)
            else:
                print(_c("Invalid option.", "red"))

    def _print_menu(self) -> None:
        """Print the main menu options."""
        print(
            """
1.  Investigate actor (manual input)
2.  Load from crawler output (JSON file)
3.  View watchlist
4.  Add actor to watchlist
5.  Remove from watchlist
6.  Pause/Resume tracking
7.  View unread alerts
8.  View all alerts for actor
9.  Start auto scheduler
10. Stop scheduler
11. Generate report
12. Export CSV
13. View database stats
14. Exit
"""
        )

    def _build_identifier(self, prompt: str, id_type: str) -> Identifier | None:
        """Ask the user for a value; return an Identifier if provided, else None."""
        value = input(prompt).strip()
        return Identifier(type=id_type, value=value) if value else None

    def _investigate_manual(self) -> None:
        """Collect identifiers from manual user input, run an investigation, and offer follow-ups."""
        identifiers = []
        for prompt, id_type in [
            ("Enter username (or press Enter to skip): ", "username"),
            ("Enter email (or press Enter to skip): ", "email"),
            ("Enter domain (or press Enter to skip): ", "domain"),
            ("Enter crypto wallet (or press Enter to skip): ", "crypto"),
            ("Enter PGP fingerprint (or press Enter to skip): ", "pgp"),
        ]:
            ident = self._build_identifier(prompt, id_type)
            if ident:
                identifiers.append(ident)

        if not identifiers:
            print(_c("No identifiers provided.", "yellow"))
            return

        actor_id = input("Actor ID (label for this actor): ").strip() or None
        investigation_id = f"MANUAL-{actor_id or 'UNKNOWN'}-{int(datetime.now(timezone.utc).timestamp())}"

        investigation = InvestigationInput(
            investigation_id=investigation_id,
            actor_id=actor_id,
            identifiers=identifiers,
        )

        result = self.engine.run(investigation)
        self.db.save_investigation(result)
        self._display_results(result)

        if actor_id and input("Add to watchlist? [y/N]: ").strip().lower() == "y":
            entry = WatchlistEntry(
                actor_id=actor_id,
                handle=actor_id,
                identifiers=[{"type": i.type, "value": i.value} for i in identifiers],
            )
            self.watchlist.add(entry)
            print(_c(f"Added {actor_id} to watchlist.", "green"))

        if input("Generate report? [y/N]: ").strip().lower() == "y":
            paths = self.reporter.generate_all(result, actor_id or "unknown")
            print(_c(f"Reports generated: {paths}", "green"))

    def _investigate_from_crawler(self) -> None:
        """Load, clean, and investigate a crawler JSON export."""
        path = input("Path to crawler JSON file: ").strip()
        try:
            investigation = self.cleaner.clean_and_prepare(path)
        except Exception as e:
            print(_c(f"Failed to load/clean crawler output: {e}", "red"))
            return

        result = self.engine.run(investigation)
        self.db.save_investigation(result)
        self._display_results(result)

        if input("Generate report? [y/N]: ").strip().lower() == "y":
            handle = investigation.actor_id or investigation.investigation_id
            paths = self.reporter.generate_all(result, handle)
            print(_c(f"Reports generated: {paths}", "green"))

    def _display_results(self, result: InvestigationResult) -> None:
        """Print a colorized summary of an investigation's findings."""
        print(_c(f"\n{len(result.findings)} findings for {result.investigation_id}", "cyan"))
        for finding in result.findings:
            line = (
                f"[FINDING] {finding.finding_type}: {finding.value} "
                f"via {finding.source} (confidence: {finding.confidence * 100:.0f}%)"
            )
            print(_c(line, "green" if finding.confidence > 0.7 else "yellow"))
        if result.errors:
            for err in result.errors:
                print(_c(f"[ERROR] {err}", "red"))

    def _view_watchlist(self) -> None:
        """Print all active watchlist entries."""
        entries = self.watchlist.all_active()
        if not entries:
            print("Watchlist is empty.")
            return
        for e in entries:
            print(f"{e.actor_id} ({e.handle}) — next scan: {e.next_scan} — scans: {e.scan_count}")

    def _add_to_watchlist(self) -> None:
        """Prompt for actor details and add them to the watchlist."""
        actor_id = input("Actor ID: ").strip()
        handle = input("Handle: ").strip() or actor_id
        interval = input("Scan interval hours [6]: ").strip()
        interval_hours = int(interval) if interval.isdigit() else 6

        entry = WatchlistEntry(actor_id=actor_id, handle=handle, interval_hours=interval_hours)
        self.watchlist.add(entry)
        print(_c(f"{actor_id} added to watchlist.", "green"))

    def _remove_from_watchlist(self) -> None:
        """Prompt for an actor ID and remove them from the watchlist."""
        actor_id = input("Actor ID to remove: ").strip()
        self.watchlist.remove(actor_id)
        print(_c(f"{actor_id} removed.", "green"))

    def _pause_resume(self) -> None:
        """Prompt for an actor ID and toggle their tracking status."""
        actor_id = input("Actor ID: ").strip()
        action = input("Pause or Resume? [p/r]: ").strip().lower()
        if action == "p":
            self.watchlist.pause(actor_id)
        elif action == "r":
            self.watchlist.resume(actor_id)
        print(_c("Done.", "green"))

    def _view_unread_alerts(self) -> None:
        """Print all unread alerts."""
        alerts = self.alerts.get_unread()
        if not alerts:
            print("No unread alerts.")
            return
        for a in alerts:
            print(_c(f"[ALERT] {a['message']}", "yellow"))

    def _view_actor_alerts(self) -> None:
        """Print all alerts for a specific actor."""
        actor_id = input("Actor ID: ").strip()
        alerts = self.alerts.get_all(actor_id=actor_id)
        if not alerts:
            print("No alerts for this actor.")
            return
        for a in alerts:
            print(f"{a['created_at']}: {a['message']}")

    def _generate_report(self) -> None:
        """Regenerate reports for an actor from their stored findings."""
        actor_id = input("Actor ID: ").strip()

        raw_findings = self.db.get_previous_findings(actor_id)
        if not raw_findings:
            print(_c("No findings stored for this actor.", "yellow"))
            return

        findings = [
            Finding(**{k: v for k, v in rf.items() if k in Finding.model_fields})
            for rf in raw_findings
        ]

        result = InvestigationResult(
            investigation_id=f"REPORT-{actor_id}",
            actor_id=actor_id,
            findings=findings,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        paths = self.reporter.generate_all(result, actor_id)
        print(_c(f"Reports generated: {paths}", "green"))

    def _export_csv(self) -> None:
        """Export an actor's findings to CSV."""
        actor_id = input("Actor ID: ").strip()
        path = self.db.export_csv(actor_id, f"reports/{actor_id}_export.csv")
        print(_c(f"Exported to {path}", "green"))

    def _view_stats(self) -> None:
        """Print database, watchlist, and alert statistics."""
        print(_c("Database stats:", "cyan"), self.db.get_stats())
        print(_c("Watchlist stats:", "cyan"), self.watchlist.get_stats())
        print(_c("Alert stats:", "cyan"), self.alerts.get_stats())


def _cli_from_flags(args: argparse.Namespace) -> InvestigationInput | None:
    """Build an InvestigationInput from CLI flags, or None if no identifiers were given."""
    identifiers = []
    if args.username:
        identifiers.append(Identifier(type="username", value=args.username))
    if args.domain:
        identifiers.append(Identifier(type="domain", value=args.domain))
    if args.email:
        identifiers.append(Identifier(type="email", value=args.email))
    if args.ip:
        identifiers.append(Identifier(type="ip", value=args.ip))

    if not identifiers:
        return None

    label = args.username or args.domain or args.ip or args.email or "run"
    return InvestigationInput(
        investigation_id=f"CLI-{label}-{int(datetime.now(timezone.utc).timestamp())}",
        identifiers=identifiers,
    )


def main() -> None:
    """Entrypoint: run from CLI flags if given, otherwise launch the interactive menu."""
    parser = argparse.ArgumentParser(description="OSINT Engine — SIH26151")
    parser.add_argument("--username")
    parser.add_argument("--domain")
    parser.add_argument("--email")
    parser.add_argument("--ip")
    args = parser.parse_args()

    cli = OSINTCli()

    investigation = _cli_from_flags(args)
    if investigation:
        result = cli.engine.run(investigation)
        cli.db.save_investigation(result)
        cli._display_results(result)
    else:
        cli.run_menu()


if __name__ == "__main__":
    main()
