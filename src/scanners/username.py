# username.py — Username scanner using Sherlock + Maigret

import subprocess, json, os, re, time, random
from .base import Scanner
from ..models import Finding, Evidence

class UsernameScanner(Scanner):
    name = "username"
    supported_types = {"username"}

    def scan(self, identifier, investigation_id, actor_id):
        results = []
        val = identifier.value

        results += self._sherlock(val, investigation_id, actor_id)
        results += self._maigret(val, investigation_id, actor_id)
        results += self._blackbird(val, investigation_id, actor_id)

        return results

    def _sherlock(self, username, iid, aid):
        out = []
        try:
            proc = subprocess.run(
                ["sherlock", username, "--print-found", "--timeout", "10"],
                capture_output=True, text=True, timeout=120
            )
            for line in proc.stdout.splitlines():
                if "[+]" in line:
                    m = re.search(r'\[(.+?)\]:\s*(https?://\S+)', line)
                    if m:
                        platform, url = m.group(1).strip(), m.group(2).strip()
                        out.append(Finding(
                            investigation_id=iid, actor_id=aid,
                            finding_type="username", value=username,
                            source="sherlock", source_url=url,
                            confidence=0.75,
                            evidence=[Evidence(source="sherlock", source_url=url,
                                               title=f"Found on {platform}")],
                            metadata={"platform": platform}
                        ))
        except FileNotFoundError:
            pass
        except subprocess.TimeoutExpired:
            pass
        return out

    def _maigret(self, username, iid, aid):
        out = []
        tmp = f"/tmp/maigret_{username}_{int(time.time())}.json"
        try:
            subprocess.run(
                ["maigret", username, "--json", tmp, "--timeout", "10", "--no-progressbar"],
                capture_output=True, text=True, timeout=180
            )
            if os.path.exists(tmp):
                data = json.load(open(tmp))
                for site, info in data.items():
                    if info.get("status", {}).get("status") == "Claimed":
                        url = info.get("url_user", "")
                        out.append(Finding(
                            investigation_id=iid, actor_id=aid,
                            finding_type="username", value=username,
                            source="maigret", source_url=url,
                            confidence=0.80,
                            evidence=[Evidence(source="maigret", source_url=url,
                                               title=f"Maigret: {site}")],
                            metadata={"platform": site}
                        ))
                os.remove(tmp)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return out

    def _blackbird(self, username, iid, aid):
        """Blackbird — 50+ platforms, no key needed"""
        out = []
        try:
            import requests
            r = requests.get(
                f"https://blackbird-osint.com/api/user/{username}",
                timeout=10
            )
            if r.status_code == 200:
                for item in r.json().get("results", []):
                    if item.get("found"):
                        out.append(Finding(
                            investigation_id=iid, actor_id=aid,
                            finding_type="username", value=username,
                            source="blackbird", source_url=item.get("url", ""),
                            confidence=0.70,
                            metadata={"platform": item.get("site", "")}
                        ))
        except Exception:
            pass
        return out

