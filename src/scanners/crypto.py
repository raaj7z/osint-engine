from __future__ import annotations

import os
import re

import requests

from .base import Scanner
from ..models import Evidence, Finding


class CryptoScanner(Scanner):
    name = "crypto"
    supported_types = {"crypto"}

    WALLET_PATTERNS = {
        "bitcoin": r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$",
        "bitcoin_bech32": r"^bc1[a-z0-9]{39,59}$",
        "ethereum": r"^0x[a-fA-F0-9]{40}$",
        "monero": r"^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$",
        "litecoin": r"^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$",
    }

    def scan(
        self,
        identifier,
        investigation_id,
        actor_id=None,
        run_id=None,
    ):
        address = identifier.value.strip()
        wallet_type = self._detect_type(address)

        if wallet_type == "unknown":
            return []

        results = []

        if wallet_type in ("bitcoin", "bitcoin_bech32"):
            results += self._blockchain_info(
                address,
                investigation_id,
                actor_id,
                run_id,
            )
            results += self._bitcoin_abuse(
                address,
                investigation_id,
                actor_id,
                run_id,
            )

        elif wallet_type == "ethereum":
            results += self._etherscan(
                address,
                investigation_id,
                actor_id,
                run_id,
            )

        elif wallet_type == "monero":
            results += self._xmrchain(
                address,
                investigation_id,
                actor_id,
                run_id,
            )

        if wallet_type != "monero":
            results += self._blockchair(
                address,
                wallet_type,
                investigation_id,
                actor_id,
                run_id,
            )

        return results

    def _detect_type(self, address):
        for wallet_type, pattern in self.WALLET_PATTERNS.items():
            if re.match(pattern, address):
                return wallet_type
        return "unknown"

    def _blockchain_info(
        self,
        address,
        investigation_id,
        actor_id,
        run_id,
    ):
        try:
            response = requests.get(
                f"https://blockchain.info/rawaddr/{address}",
                params={"limit": 5},
                timeout=10,
            )

            if response.status_code != 200:
                return []

            data = response.json()

            balance_satoshi = data.get("final_balance", 0)
            transactions = data.get("txs", [])

            return [
                Finding(
                    investigation_id=investigation_id,
                    actor_id=actor_id,
                    run_id=run_id,
                    finding_type="crypto",
                    value=address,
                    source="blockchain.info",
                    source_url=(
                        f"https://www.blockchain.com/btc/address/"
                        f"{address}"
                    ),
                    confidence=0.95,
                    evidence=[
                        Evidence(
                            source="blockchain.info",
                            source_url=(
                                f"https://www.blockchain.com/btc/address/"
                                f"{address}"
                            ),
                            title=(
                                f"Bitcoin wallet: "
                                f"{address[:20]}..."
                            ),
                            excerpt=(
                                f"Balance: "
                                f"{balance_satoshi / 1e8:.8f} BTC | "
                                f"Txns: {data.get('n_tx', 0)}"
                            ),
                        )
                    ],
                    metadata={
                        "wallet_type": "bitcoin",
                        "balance_satoshi": balance_satoshi,
                        "balance_btc": balance_satoshi / 1e8,
                        "total_received": (
                            data.get("total_received", 0) / 1e8
                        ),
                        "total_sent": (
                            data.get("total_sent", 0) / 1e8
                        ),
                        "tx_count": data.get("n_tx", 0),
                        "first_tx": (
                            transactions[-1].get("time", "")
                            if transactions
                            else ""
                        ),
                        "last_tx": (
                            transactions[0].get("time", "")
                            if transactions
                            else ""
                        ),
                    },
                )
            ]

        except Exception:
            return []

    def _bitcoin_abuse(
        self,
        address,
        investigation_id,
        actor_id,
        run_id,
    ):
        try:
            response = requests.get(
                "https://www.bitcoinabuse.com/api/reports/check",
                params={
                    "address": address,
                    "api_token": os.getenv(
                        "BITCOIN_ABUSE_KEY",
                        "",
                    ),
                },
                timeout=10,
            )

            if response.status_code != 200:
                return []

            data = response.json()
            count = data.get("count", 0)

            if count <= 0:
                return []

            return [
                Finding(
                    investigation_id=investigation_id,
                    actor_id=actor_id,
                    run_id=run_id,
                    finding_type="crypto",
                    value=address,
                    source="bitcoin_abuse",
                    source_url=(
                        f"https://www.bitcoinabuse.com/reports/"
                        f"{address}"
                    ),
                    confidence=0.90,
                    evidence=[
                        Evidence(
                            source="bitcoin_abuse",
                            source_url=(
                                f"https://www.bitcoinabuse.com/reports/"
                                f"{address}"
                            ),
                            title=(
                                f"Reported abuse: "
                                f"{address[:20]}..."
                            ),
                            excerpt=(
                                f"Reports: {count} | "
                                f"Types: {data.get('recent', {})}"
                            ),
                        )
                    ],
                    metadata={
                        "abuse_count": count,
                        "recent": data.get("recent", {}),
                    },
                )
            ]

        except Exception:
            return []

    def _etherscan(
        self,
        address,
        investigation_id,
        actor_id,
        run_id,
    ):
        api_key = os.getenv(
            "ETHERSCAN_API_KEY",
            "",
        )

        if not api_key:
            return []

        try:
            response = requests.get(
                "https://api.etherscan.io/api",
                params={
                    "module": "account",
                    "action": "balance",
                    "address": address,
                    "tag": "latest",
                    "apikey": api_key,
                },
                timeout=10,
            )

            if response.status_code != 200:
                return []

            payload = response.json()

            if payload.get("status") != "1":
                return []

            balance_wei = int(
                payload.get("result", 0)
            )
            balance_eth = balance_wei / 1e18

            transaction_response = requests.get(
                "https://api.etherscan.io/api",
                params={
                    "module": "account",
                    "action": "txlist",
                    "address": address,
                    "startblock": 0,
                    "endblock": 99999999,
                    "page": 1,
                    "offset": 5,
                    "sort": "desc",
                    "apikey": api_key,
                },
                timeout=10,
            )

            transactions = []

            if transaction_response.status_code == 200:
                transactions = (
                    transaction_response
                    .json()
                    .get("result", [])
                )

            return [
                Finding(
                    investigation_id=investigation_id,
                    actor_id=actor_id,
                    run_id=run_id,
                    finding_type="crypto",
                    value=address,
                    source="etherscan",
                    source_url=(
                        f"https://etherscan.io/address/{address}"
                    ),
                    confidence=0.95,
                    evidence=[
                        Evidence(
                            source="etherscan",
                            source_url=(
                                f"https://etherscan.io/address/"
                                f"{address}"
                            ),
                            title=(
                                f"Ethereum wallet: "
                                f"{address[:20]}..."
                            ),
                            excerpt=(
                                f"Balance: {balance_eth:.6f} ETH | "
                                f"Recent txns: {len(transactions)}"
                            ),
                        )
                    ],
                    metadata={
                        "wallet_type": "ethereum",
                        "balance_wei": balance_wei,
                        "balance_eth": balance_eth,
                        "recent_tx_count": len(transactions),
                    },
                )
            ]

        except Exception:
            return []

    def _xmrchain(
        self,
        address,
        investigation_id,
        actor_id,
        run_id,
    ):
        return [
            Finding(
                investigation_id=investigation_id,
                actor_id=actor_id,
                run_id=run_id,
                finding_type="crypto",
                value=address,
                source="xmrchain",
                source_url=(
                    f"https://xmrchain.net/search/"
                    f"{address}"
                ),
                confidence=0.50,
                evidence=[
                    Evidence(
                        source="xmrchain",
                        source_url=(
                            f"https://xmrchain.net/search/"
                            f"{address}"
                        ),
                        title="Monero address detected",
                        excerpt=(
                            "Monero transactions provide limited "
                            "public blockchain attribution data."
                        ),
                    )
                ],
                metadata={
                    "wallet_type": "monero",
                    "privacy": "high",
                },
            )
        ]

    def _blockchair(
        self,
        address,
        wallet_type,
        investigation_id,
        actor_id,
        run_id,
    ):
        chain_map = {
            "bitcoin": "bitcoin",
            "bitcoin_bech32": "bitcoin",
            "ethereum": "ethereum",
            "litecoin": "litecoin",
        }

        chain = chain_map.get(wallet_type)

        if not chain:
            return []

        try:
            response = requests.get(
                (
                    f"https://api.blockchair.com/{chain}/"
                    f"dashboards/address/{address}"
                ),
                timeout=10,
            )

            if response.status_code != 200:
                return []

            data = (
                response.json()
                .get("data", {})
                .get(address, {})
            )

            address_data = data.get(
                "address",
                {},
            )

            balance = address_data.get(
                "balance",
                0,
            )

            transaction_count = address_data.get(
                "transaction_count",
                0,
            )

            return [
                Finding(
                    investigation_id=investigation_id,
                    actor_id=actor_id,
                    run_id=run_id,
                    finding_type="crypto",
                    value=address,
                    source="blockchair",
                    source_url=(
                        f"https://blockchair.com/{chain}/address/"
                        f"{address}"
                    ),
                    confidence=0.85,
                    evidence=[
                        Evidence(
                            source="blockchair",
                            source_url=(
                                f"https://blockchair.com/{chain}/"
                                f"address/{address}"
                            ),
                            title=(
                                f"Blockchair: {chain} "
                                f"{address[:20]}..."
                            ),
                            excerpt=(
                                f"Balance: {balance} | "
                                f"Txns: {transaction_count}"
                            ),
                        )
                    ],
                    metadata={
                        "chain": chain,
                        "balance": balance,
                        "tx_count": transaction_count,
                        "first_seen": address_data.get(
                            "first_seen_receiving",
                            "",
                        ),
                        "last_seen": address_data.get(
                            "last_seen_receiving",
                            "",
                        ),
                        "risk_score": address_data.get(
                            "risk_score",
                            "",
                        ),
                    },
                )
            ]

        except Exception:
            return []
