# crypto.py — Crypto wallet scanner
# Uses: Blockchain.info (BTC), Etherscan (ETH), Blockchair (multi), XMRChain (XMR)

import requests, os, re
from .base import Scanner
from ..models import Finding, Evidence

class CryptoScanner(Scanner):
    name = "crypto"
    supported_types = {"crypto"}

    # Regex to detect wallet type from address format
    WALLET_PATTERNS = {
        "bitcoin":   r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$",
        "bitcoin_bech32": r"^bc1[a-z0-9]{39,59}$",
        "ethereum":  r"^0x[a-fA-F0-9]{40}$",
        "monero":    r"^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$",
        "litecoin":  r"^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$",
    }

    def scan(self, identifier, investigation_id, actor_id):
        address = identifier.value.strip()
        wallet_type = self._detect_type(address)
        results = []

        if wallet_type in ("bitcoin", "bitcoin_bech32"):
            results += self._blockchain_info(address, investigation_id, actor_id)
            results += self._bitcoin_abuse(address, investigation_id, actor_id)

        elif wallet_type == "ethereum":
            results += self._etherscan(address, investigation_id, actor_id)

        elif wallet_type == "monero":
            results += self._xmrchain(address, investigation_id, actor_id)

        # Blockchair covers BTC, ETH, LTC and more
        if wallet_type != "monero":
            results += self._blockchair(address, wallet_type, investigation_id, actor_id)

        return results

    def _detect_type(self, address):
        for wtype, pattern in self.WALLET_PATTERNS.items():
            if re.match(pattern, address):
                return wtype
        return "unknown"

    def _blockchain_info(self, address, iid, aid):
        out = []
        try:
            r = requests.get(
                f"https://blockchain.info/rawaddr/{address}",
                params={"limit": 5}, timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                out.append(Finding(
                    investigation_id=iid, actor_id=aid,
                    finding_type="crypto", value=address,
                    source="blockchain.info",
                    source_url=f"https://www.blockchain.com/btc/address/{address}",
                    confidence=0.95,
                    evidence=[Evidence(
                        source="blockchain.info",
                        title=f"Bitcoin wallet: {address[:20]}...",
                        excerpt=f"Balance: {data.get('final_balance',0)/1e8:.8f} BTC | Txns: {data.get('n_tx',0)}"
                    )],
                    metadata={
                        "wallet_type": "bitcoin",
                        "balance_satoshi": data.get("final_balance", 0),
                        "balance_btc": data.get("final_balance", 0) / 1e8,
                        "total_received": data.get("total_received", 0) / 1e8,
                        "total_sent": data.get("total_sent", 0) / 1e8,
                        "tx_count": data.get("n_tx", 0),
                        "first_tx": data.get("txs", [{}])[-1].get("time", "") if data.get("txs") else "",
                        "last_tx": data.get("txs", [{}])[0].get("time", "") if data.get("txs") else "",
                    }
                ))
        except Exception:
            pass
        return out

    def _bitcoin_abuse(self, address, iid, aid):
        """BitcoinAbuse — check if address is reported for scams/ransomware"""
        out = []
        try:
            r = requests.get(
                f"https://www.bitcoinabuse.com/api/reports/check",
                params={"address": address, "api_token": os.getenv("BITCOIN_ABUSE_KEY", "")},
                timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                count = data.get("count", 0)
                if count > 0:
                    out.append(Finding(
                        investigation_id=iid, actor_id=aid,
                        finding_type="crypto", value=address,
                        source="bitcoin_abuse",
                        source_url=f"https://www.bitcoinabuse.com/reports/{address}",
                        confidence=0.90,
                        evidence=[Evidence(
                            source="bitcoin_abuse",
                            title=f"Reported abuse: {address[:20]}...",
                            excerpt=f"Reports: {count} | Types: {data.get('recent',{})}"
                        )],
                        metadata={"abuse_count": count, "recent": data.get("recent", {})}
                    ))
        except Exception:
            pass
        return out

    def _etherscan(self, address, iid, aid):
        out = []
        key = os.getenv("ETHERSCAN_API_KEY", "")
        if not key:
            return out
        try:
            r = requests.get(
                "https://api.etherscan.io/api",
                params={
                    "module": "account", "action": "balance",
                    "address": address, "tag": "latest", "apikey": key
                }, timeout=10
            )
            if r.status_code == 200 and r.json().get("status") == "1":
                balance_wei = int(r.json().get("result", 0))
                balance_eth = balance_wei / 1e18

                # Get transaction count
                txn_r = requests.get(
                    "https://api.etherscan.io/api",
                    params={
                        "module": "account", "action": "txlist",
                        "address": address, "startblock": 0,
                        "endblock": 99999999, "page": 1,
                        "offset": 5, "sort": "desc", "apikey": key
                    }, timeout=10
                )
                txns = txn_r.json().get("result", []) if txn_r.status_code == 200 else []

                out.append(Finding(
                    investigation_id=iid, actor_id=aid,
                    finding_type="crypto", value=address,
                    source="etherscan",
                    source_url=f"https://etherscan.io/address/{address}",
                    confidence=0.95,
                    evidence=[Evidence(
                        source="etherscan",
                        title=f"Ethereum wallet: {address[:20]}...",
                        excerpt=f"Balance: {balance_eth:.6f} ETH | Txns: {len(txns)}"
                    )],
                    metadata={
                        "wallet_type": "ethereum",
                        "balance_wei": balance_wei,
                        "balance_eth": balance_eth,
                        "recent_tx_count": len(txns)
                    }
                ))
        except Exception:
            pass
        return out

    def _xmrchain(self, address, iid, aid):
        """Monero — limited info due to privacy design"""
        out = []
        try:
            out.append(Finding(
                investigation_id=iid, actor_id=aid,
                finding_type="crypto", value=address,
                source="manual_note", confidence=0.50,
                evidence=[Evidence(
                    source="xmrchain",
                    title="Monero address detected",
                    excerpt="Monero transactions are private by design — limited blockchain analysis possible"
                )],
                metadata={"wallet_type": "monero", "privacy": "high"}
            ))
        except Exception:
            pass
        return out

    def _blockchair(self, address, wallet_type, iid, aid):
        """Blockchair — multi-chain explorer, free tier"""
        out = []
        chain_map = {
            "bitcoin": "bitcoin", "bitcoin_bech32": "bitcoin",
            "ethereum": "ethereum", "litecoin": "litecoin"
        }
        chain = chain_map.get(wallet_type, "bitcoin")
        try:
            r = requests.get(
                f"https://api.blockchair.com/{chain}/dashboards/address/{address}",
                timeout=10
            )
            if r.status_code == 200:
                data = r.json().get("data", {}).get(address, {})
                addr_data = data.get("address", {})
                out.append(Finding(
                    investigation_id=iid, actor_id=aid,
                    finding_type="crypto", value=address,
                    source="blockchair",
                    source_url=f"https://blockchair.com/{chain}/address/{address}",
                    confidence=0.85,
                    evidence=[Evidence(
                        source="blockchair",
                        title=f"Blockchair: {chain} {address[:20]}...",
                        excerpt=f"Balance: {addr_data.get('balance',0)} | Txns: {addr_data.get('transaction_count',0)}"
                    )],
                    metadata={
                        "chain": chain,
                        "balance": addr_data.get("balance", 0),
                        "tx_count": addr_data.get("transaction_count", 0),
                        "first_seen": addr_data.get("first_seen_receiving", ""),
                        "last_seen": addr_data.get("last_seen_receiving", ""),
                        "risk_score": data.get("address", {}).get("risk_score", "")
                    }
                ))
        except Exception:
            pass
        return out

