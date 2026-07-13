"""
Synthetic DNS query log generator.

Modeled on a BIND/dnsmasq-style internal resolver query log. Supports
injecting C2 beaconing patterns: a single internal host querying a
suspicious domain at regular intervals, a classic detection signal for
malware command-and-control.
"""
import random
from datetime import datetime, timedelta
from typing import Optional

from app.core.config import INTERNAL_SUBNET

BENIGN_DOMAINS = [
    "google.com", "microsoft.com", "github.com", "slack.com",
    "office365.com", "zoom.us", "cloudflare.com", "amazonaws.com",
    "akamai.net", "windowsupdate.com", "apple.com", "linkedin.com",
]


class DnsLogGenerator:
    def __init__(self, seed: int, base_time: Optional[datetime] = None, resolver_host: str = "dns-internal01"):
        self.rng = random.Random(seed)
        self.base_time = base_time or datetime(2026, 6, 18, 0, 0, 0)
        self.resolver_host = resolver_host
        self.entries: list[dict] = []

    def _internal_ip(self) -> str:
        return f"{INTERNAL_SUBNET}{self.rng.randint(2, 254)}"

    def add_event(self, timestamp: datetime, client_ip: str, query: str,
                  qtype: str = "A", resolved_ip: str = "", is_attack: bool = False):
        entry = {
            "timestamp": timestamp.isoformat(),
            "host": self.resolver_host,
            "source": "dns",
            "client_ip": client_ip,
            "query": query,
            "qtype": qtype,
            "resolved_ip": resolved_ip,
            "is_attack": is_attack,
        }
        self.entries.append(entry)
        return entry

    def generate_benign_traffic(self, count: int, time_window_hours: int = 24):
        for _ in range(count):
            ts = self.base_time + timedelta(seconds=self.rng.randint(0, time_window_hours * 3600))
            client = self._internal_ip()
            domain = self.rng.choice(BENIGN_DOMAINS)
            resolved = f"93.184.{self.rng.randint(1,254)}.{self.rng.randint(1,254)}"
            self.add_event(ts, client, domain, "A", resolved)

    def inject_c2_beacon(self, infected_host_ip: str, c2_domain: str,
                          start_time: datetime, interval_seconds: int = 60,
                          beacon_count: int = 25, c2_resolved_ip: str = "203.0.113.77"):
        """
        Inject a regular-interval beaconing pattern: the infected host
        queries the C2 domain roughly every `interval_seconds`, with small
        jitter (as real malware does to evade naive interval detection).
        """
        t = start_time
        for _ in range(beacon_count):
            jitter = self.rng.uniform(-3, 3)
            self.add_event(t, infected_host_ip, c2_domain, "A", c2_resolved_ip, is_attack=True)
            t += timedelta(seconds=interval_seconds + jitter)
        return t

    def sorted_entries(self):
        return sorted(self.entries, key=lambda e: e["timestamp"])

    def render_text(self) -> str:
        lines = []
        for e in self.sorted_entries():
            ts = datetime.fromisoformat(e["timestamp"]).strftime("%d-%b-%Y %H:%M:%S")
            lines.append(
                f"{ts} client {e['client_ip']}#{self.rng.randint(10000,65000)}: "
                f"query: {e['query']} IN {e['qtype']} + ({e['resolved_ip']})"
            )
        return "\n".join(lines)

    def player_view(self) -> list[dict]:
        return [{k: v for k, v in e.items() if k != "is_attack"} for e in self.sorted_entries()]
