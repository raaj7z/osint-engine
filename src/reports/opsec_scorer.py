"""OPSEC exposure scoring for the OSINT engine.

Produces a 0-100 score estimating how exposed a threat actor is to
de-anonymization, broken down across four risk categories.
"""

from ..models import Finding


class OPSECScorer:
    """Scores a set of findings for a threat actor's overall OPSEC exposure."""

    def score(self, findings: list[Finding]) -> dict:
        """Compute the total OPSEC score, category breakdown, and risk level for a finding set."""
        breakdown: list[dict] = []

        identity_score = self._score_identity(findings, breakdown)
        platform_score = self._score_platform(findings, breakdown)
        infra_score = self._score_infrastructure(findings, breakdown)
        financial_score = self._score_financial(findings, breakdown)

        total = min(identity_score + platform_score + infra_score + financial_score, 100.0)
        risk_level = self._risk_level(total)

        summary = (
            f"OPSEC score {total:.1f}/100 ({risk_level} risk) — "
            f"identity {identity_score:.1f}, platform {platform_score:.1f}, "
            f"infrastructure {infra_score:.1f}, financial {financial_score:.1f}"
        )

        return {
            "total_score": total,
            "risk_level": risk_level,
            "categories": {
                "identity_exposure": identity_score,
                "platform_presence": platform_score,
                "infrastructure": infra_score,
                "financial_exposure": financial_score,
            },
            "breakdown": breakdown,
            "summary": summary,
        }

    def _add(self, breakdown: list[dict], category: str, points: float, reason: str) -> None:
        """Record a scoring contribution in the breakdown list."""
        breakdown.append({"category": category, "points": points, "reason": reason})

    def _score_identity(self, findings: list[Finding], breakdown: list[dict]) -> float:
        """Score identity exposure: emails, breaches, PGP-linked emails, real names. Max 25."""
        score = 0.0

        emails = [f for f in findings if f.finding_type == "email"]
        score += len(emails) * 5
        for f in emails:
            self._add(breakdown, "identity_exposure", 5, f"Email found: {f.value}")

        breaches = [f for f in findings if "breach" in f.source.lower()]
        score += len(breaches) * 3
        for f in breaches:
            self._add(breakdown, "identity_exposure", 3, f"Breach record: {f.value}")

        pgp_with_email = [
            f
            for f in findings
            if f.finding_type == "pgp" and "@" in (f.metadata.get("email") or "")
        ]
        if pgp_with_email:
            score += 8
            self._add(breakdown, "identity_exposure", 8, "PGP key contains an email address")

        real_names = [f for f in findings if f.metadata.get("real_name")]
        if real_names:
            score += 5
            self._add(breakdown, "identity_exposure", 5, "Real name found")

        return min(score, 25.0)

    def _score_platform(self, findings: list[Finding], breakdown: list[dict]) -> float:
        """Score platform presence: unique platforms, cross-platform reuse, dark-web forums. Max 25."""
        score = 0.0

        username_findings = [f for f in findings if f.finding_type == "username"]
        platforms = {f.metadata.get("platform", f.source) for f in username_findings}
        score += len(platforms) * 2
        for platform in platforms:
            self._add(breakdown, "platform_presence", 2, f"Username found on {platform}")

        if len(platforms) >= 5:
            score += 5
            self._add(breakdown, "platform_presence", 5, "Same username reused on 5+ platforms")

        forum_profiles = [f for f in findings if f.finding_type == "forum_profile"]
        if forum_profiles:
            score += 3
            self._add(breakdown, "platform_presence", 3, "Forum profile found on dark web")

        return min(score, 25.0)

    def _score_infrastructure(self, findings: list[Finding], breakdown: list[dict]) -> float:
        """Score infrastructure exposure: clearnet/onion SSL links, server leaks, IPs, Tor, misconfigs. Max 25."""
        score = 0.0

        ssl_linked = [f for f in findings if f.metadata.get("ssl_linked_onion")]
        if ssl_linked:
            score += 10
            self._add(breakdown, "infrastructure", 10, "Clearnet domain linked to onion via SSL cert")

        server_exposed = [
            f for f in findings if f.finding_type == "infrastructure" and f.metadata.get("server")
        ]
        if server_exposed:
            score += 8
            self._add(breakdown, "infrastructure", 8, "Server software exposed")

        ip_findings = [f for f in findings if f.finding_type == "ip"]
        if ip_findings:
            score += 5
            self._add(breakdown, "infrastructure", 5, "IP address exposed")

        tor_exit = [f for f in findings if f.metadata.get("is_tor_exit")]
        if tor_exit:
            score += 5
            self._add(breakdown, "infrastructure", 5, "Tor exit node identified")

        misconfigs = [
            f for f in findings if "misconfig" in (f.metadata.get("category") or "").lower()
        ]
        score += len(misconfigs) * 3
        for f in misconfigs:
            self._add(breakdown, "infrastructure", 3, f"Misconfiguration: {f.value}")

        return min(score, 25.0)

    def _score_financial(self, findings: list[Finding], breakdown: list[dict]) -> float:
        """Score financial exposure: crypto wallets, transaction history, abuse flags, currencies. Max 25."""
        score = 0.0

        wallets = [f for f in findings if f.finding_type == "crypto"]
        score += len(wallets) * 8
        for f in wallets:
            self._add(breakdown, "financial_exposure", 8, f"Crypto wallet found: {f.value}")

        with_history = [f for f in wallets if f.metadata.get("has_transactions")]
        if with_history:
            score += 5
            self._add(breakdown, "financial_exposure", 5, "Wallet has transaction history")

        flagged = [f for f in wallets if f.metadata.get("bitcoinabuse_flagged")]
        if flagged:
            score += 10
            self._add(breakdown, "financial_exposure", 10, "Wallet flagged on BitcoinAbuse")

        currencies = {f.metadata.get("currency") for f in wallets if f.metadata.get("currency")}
        if len(currencies) > 1:
            extra = len(currencies) - 1
            score += extra * 3
            self._add(breakdown, "financial_exposure", extra * 3, f"{extra} additional currencies found")

        return min(score, 25.0)

    def _risk_level(self, total: float) -> str:
        """Map a total score to a risk-level label."""
        if total <= 25:
            return "LOW"
        if total <= 50:
            return "MEDIUM"
        if total <= 75:
            return "HIGH"
        return "CRITICAL"
