from __future__ import annotations

from collections import defaultdict

from ..models import Finding


class OPSECScorer:
    MAX_TOTAL = 100.0

    def score(
        self,
        findings: list[Finding],
    ) -> dict:
        breakdown: list[dict] = []

        identity = self._score_identity(
            findings,
            breakdown,
        )

        platforms = self._score_platform(
            findings,
            breakdown,
        )

        infrastructure = self._score_infrastructure(
            findings,
            breakdown,
        )

        financial = self._score_financial(
            findings,
            breakdown,
        )

        total = min(
            identity
            + platforms
            + infrastructure
            + financial,
            self.MAX_TOTAL,
        )

        risk_level = self._risk_level(
            total
        )

        return {
            "total_score": round(
                total,
                2,
            ),
            "risk_level": risk_level,
            "categories": {
                "identity_exposure": round(
                    identity,
                    2,
                ),
                "platform_presence": round(
                    platforms,
                    2,
                ),
                "infrastructure": round(
                    infrastructure,
                    2,
                ),
                "financial_exposure": round(
                    financial,
                    2,
                ),
            },
            "breakdown": breakdown,
            "summary": self._summary(
                total,
                risk_level,
                identity,
                platforms,
                infrastructure,
                financial,
            ),
        }

    def _add(
        self,
        breakdown: list[dict],
        category: str,
        points: float,
        reason: str,
        finding: Finding | None = None,
    ) -> None:
        item = {
            "category": category,
            "points": round(
                float(points),
                2,
            ),
            "reason": reason,
        }

        if finding is not None:
            item["finding_type"] = (
                finding.finding_type
            )
            item["value"] = finding.value
            item["source"] = finding.source

        breakdown.append(item)

    def _score_identity(
        self,
        findings: list[Finding],
        breakdown: list[dict],
    ) -> float:
        score = 0.0

        emails = [
            f
            for f in findings
            if f.finding_type == "email"
        ]

        for finding in emails:
            points = self._confidence_weight(
                5.0,
                finding,
            )

            score += points

            self._add(
                breakdown,
                "identity_exposure",
                points,
                "Email identifier exposed",
                finding,
            )

        breach_findings = [
            f
            for f in findings
            if "breach"
            in str(
                f.source
            ).lower()
            or "breach"
            in str(
                f.metadata.get(
                    "category",
                    ""
                )
            ).lower()
        ]

        for finding in breach_findings:
            points = self._confidence_weight(
                3.0,
                finding,
            )

            score += points

            self._add(
                breakdown,
                "identity_exposure",
                points,
                "Breach-related evidence found",
                finding,
            )

        pgp_email = [
            f
            for f in findings
            if f.finding_type == "pgp"
            and (
                f.metadata.get(
                    "email"
                )
                or "@"
                in str(
                    f.value
                )
            )
        ]

        if pgp_email:
            points = min(
                8.0,
                4.0
                + min(
                    len(pgp_email),
                    4,
                ),
            )

            score += points

            self._add(
                breakdown,
                "identity_exposure",
                points,
                "PGP evidence contains an email-linked identity",
            )

        real_names = [
            f
            for f in findings
            if f.metadata.get(
                "real_name"
            )
        ]

        if real_names:
            points = min(
                5.0,
                2.5
                + min(
                    len(real_names),
                    2
                ) * 1.25,
            )

            score += points

            self._add(
                breakdown,
                "identity_exposure",
                points,
                "Real-name metadata associated with findings",
            )

        return min(
            score,
            25.0,
        )

    def _score_platform(
        self,
        findings: list[Finding],
        breakdown: list[dict],
    ) -> float:
        score = 0.0

        platform_map: dict[
            str,
            list[Finding],
        ] = defaultdict(list)

        for finding in findings:
            if finding.finding_type not in {
                "username",
                "forum_profile",
            }:
                continue

            platform = str(
                finding.metadata.get(
                    "platform",
                    finding.source,
                )
            ).strip()

            if platform:
                platform_map[
                    platform
                ].append(finding)

        platforms = set(
            platform_map.keys()
        )

        platform_points = min(
            len(platforms) * 2.0,
            10.0,
        )

        if platform_points:
            score += platform_points

            self._add(
                breakdown,
                "platform_presence",
                platform_points,
                (
                    f"Identity identifier observed "
                    f"across {len(platforms)} platform(s)"
                ),
            )

        if len(platforms) >= 5:
            points = 5.0

            score += points

            self._add(
                breakdown,
                "platform_presence",
                points,
                "Same identifier observed across 5 or more platforms",
            )

        forum_profiles = [
            f
            for f in findings
            if f.finding_type
            == "forum_profile"
        ]

        if forum_profiles:
            points = min(
                3.0
                + (
                    max(
                        len(
                            forum_profiles
                        )
                        - 1,
                        0,
                    )
                    * 0.5
                ),
                5.0,
            )

            score += points

            self._add(
                breakdown,
                "platform_presence",
                points,
                "Forum-profile evidence found",
            )

        cross_source = self._cross_source_reuse(
            findings
        )

        if cross_source:
            points = min(
                5.0,
                len(cross_source),
            )

            score += points

            self._add(
                breakdown,
                "platform_presence",
                points,
                "Same identifier appears across multiple independent sources",
            )

        return min(
            score,
            25.0,
        )

    def _score_infrastructure(
        self,
        findings: list[Finding],
        breakdown: list[dict],
    ) -> float:
        score = 0.0

        ssl_linked = [
            f
            for f in findings
            if f.metadata.get(
                "ssl_linked_onion"
            )
        ]

        if ssl_linked:
            points = 10.0

            score += points

            self._add(
                breakdown,
                "infrastructure",
                points,
                "Clearnet infrastructure linked to an onion service through certificate evidence",
            )

        exposed_server = [
            f
            for f in findings
            if f.finding_type
            == "infrastructure"
            and (
                f.metadata.get(
                    "server"
                )
                or f.metadata.get(
                    "server_banner"
                )
            )
        ]

        if exposed_server:
            points = min(
                8.0,
                4.0
                + len(exposed_server),
            )

            score += points

            self._add(
                breakdown,
                "infrastructure",
                points,
                "Server or service fingerprint exposed",
            )

        ip_findings = [
            f
            for f in findings
            if f.finding_type == "ip"
        ]

        if ip_findings:
            points = min(
                5.0,
                2.0
                + len(ip_findings),
            )

            score += points

            self._add(
                breakdown,
                "infrastructure",
                points,
                "IP infrastructure associated with investigation evidence",
            )

        tor_exit = [
            f
            for f in findings
            if f.metadata.get(
                "is_tor_exit"
            )
        ]

        if tor_exit:
            points = 5.0

            score += points

            self._add(
                breakdown,
                "infrastructure",
                points,
                "Observed infrastructure is associated with a Tor exit node",
            )

        misconfigs = [
            f
            for f in findings
            if "misconfig"
            in str(
                f.metadata.get(
                    "category",
                    "",
                )
            ).lower()
        ]

        for finding in misconfigs:
            points = self._confidence_weight(
                3.0,
                finding,
            )

            score += points

            self._add(
                breakdown,
                "infrastructure",
                points,
                "Infrastructure misconfiguration observed",
                finding,
            )

        return min(
            score,
            25.0,
        )

    def _score_financial(
        self,
        findings: list[Finding],
        breakdown: list[dict],
    ) -> float:
        score = 0.0

        wallets = [
            f
            for f in findings
            if f.finding_type == "crypto"
        ]

        for finding in wallets:
            points = self._confidence_weight(
                6.0,
                finding,
            )

            score += points

            self._add(
                breakdown,
                "financial_exposure",
                points,
                "Cryptocurrency identifier exposed",
                finding,
            )

        with_history = [
            f
            for f in wallets
            if f.metadata.get(
                "has_transactions"
            )
        ]

        if with_history:
            points = min(
                5.0,
                2.0
                + len(
                    with_history
                ),
            )

            score += points

            self._add(
                breakdown,
                "financial_exposure",
                points,
                "Wallet activity or transaction history observed",
            )

        flagged = [
            f
            for f in wallets
            if f.metadata.get(
                "bitcoinabuse_flagged"
            )
        ]

        if flagged:
            points = min(
                10.0,
                5.0
                + len(flagged),
            )

            score += points

            self._add(
                breakdown,
                "financial_exposure",
                points,
                "Cryptocurrency address has an abuse-related flag",
            )

        currencies = {
            str(
                f.metadata.get(
                    "currency"
                )
            ).lower()
            for f in wallets
            if f.metadata.get(
                "currency"
            )
        }

        if len(currencies) > 1:
            points = min(
                3.0,
                float(
                    len(currencies)
                    - 1
                ),
            )

            score += points

            self._add(
                breakdown,
                "financial_exposure",
                points,
                (
                    f"Evidence covers "
                    f"{len(currencies)} cryptocurrency type(s)"
                ),
            )

        return min(
            score,
            25.0,
        )

    def _confidence_weight(
        self,
        points: float,
        finding: Finding,
    ) -> float:
        confidence = max(
            0.0,
            min(
                float(
                    finding.confidence
                ),
                1.0,
            ),
        )

        return points * (
            0.5 + 0.5 * confidence
        )

    def _cross_source_reuse(
        self,
        findings: list[Finding],
    ) -> set[str]:
        values: dict[
            str,
            set[str],
        ] = defaultdict(set)

        for finding in findings:
            if finding.finding_type not in {
                "username",
                "email",
                "pgp",
                "crypto",
            }:
                continue

            normalized = str(
                finding.value
            ).strip().lower()

            if not normalized:
                continue

            values[
                normalized
            ].add(
                str(
                    finding.source
                )
            )

        return {
            value
            for value, sources
            in values.items()
            if len(sources) >= 2
        }

    def _risk_level(
        self,
        total: float,
    ) -> str:
        if total <= 25:
            return "LOW"

        if total <= 50:
            return "MEDIUM"

        if total <= 75:
            return "HIGH"

        return "CRITICAL"

    def _summary(
        self,
        total: float,
        risk_level: str,
        identity: float,
        platforms: float,
        infrastructure: float,
        financial: float,
    ) -> str:
        return (
            f"OPSEC exposure score "
            f"{total:.1f}/100 "
            f"({risk_level}). "
            f"Identity: {identity:.1f}, "
            f"platform presence: {platforms:.1f}, "
            f"infrastructure: {infrastructure:.1f}, "
            f"financial exposure: {financial:.1f}."
        )
