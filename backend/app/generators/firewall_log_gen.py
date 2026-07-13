"""
Synthetic firewall/connection log generator.

Modeled on an edge firewall (iptables/pfSense-style) connection log:
action, protocol, src/dst IP and port, bytes transferred. Supports
injecting a large-volume outbound exfiltration event hidden among normal
low-volume web browsing traffic — the realistic "needle in haystack"
signal-to-noise problem of insider-threat detection.
"""
import random
from datetime import datetime, timedelta
from typing import Optional

from app.core.config import INTERNAL_SUBNET

# Plausible benign external destinations (CDNs, SaaS, cloud) with typical
# small-to-moderate transfer sizes
BENIGN_DESTINATIONS = [
    "151.101.1.140", "104.16.85.20", "13.107.42.14", "172.217.14.110",
    "20.42.65.92", "52.84.150.21", "143.204.98.27",
]


class FirewallLogGenerator:
    def __init__(self, seed: int, base_time: Optional[datetime] = None, firewall_host: str = "fw-edge01"):
        self.rng = random.Random(seed)
        self.base_time = base_time or datetime(2026, 6, 18, 0, 0, 0)
        self.firewall_host = firewall_host
        self.entries: list[dict] = []

    def _internal_ip(self) -> str:
        return f"{INTERNAL_SUBNET}{self.rng.randint(2, 254)}"

    def add_event(self, timestamp: datetime, action: str, src_ip: str, src_port: int,
                  dst_ip: str, dst_port: int, bytes_out: int, bytes_in: int,
                  proto: str = "TCP", is_attack: bool = False):
        entry = {
            "timestamp": timestamp.isoformat(),
            "host": self.firewall_host,
            "source": "firewall",
            "action": action,
            "proto": proto,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "bytes_out": bytes_out,
            "bytes_in": bytes_in,
            "is_attack": is_attack,
        }
        self.entries.append(entry)
        return entry

    def generate_benign_traffic(self, count: int, time_window_hours: int = 24):
        for _ in range(count):
            ts = self.base_time + timedelta(seconds=self.rng.randint(0, time_window_hours * 3600))
            src = self._internal_ip()
            dst = self.rng.choice(BENIGN_DESTINATIONS)
            port = self.rng.randint(40000, 65000)
            bytes_out = self.rng.randint(800, 45_000)   # normal web request size
            bytes_in = self.rng.randint(5_000, 600_000)  # normal page/asset download
            self.add_event(ts, "ALLOW", src, port, dst, 443, bytes_out, bytes_in)

    def inject_exfiltration(self, insider_host_ip: str, exfil_dst_ip: str,
                              start_time: datetime, total_bytes_out: int = 480_000_000,
                              chunk_count: int = 6):
        """
        Inject a large outbound transfer split into chunks (as real
        exfiltration over HTTPS often is, to avoid single-connection size
        alarms) occurring during an off-hours window.
        """
        t = start_time
        per_chunk = total_bytes_out // chunk_count
        port = self.rng.randint(50000, 64000)
        for _ in range(chunk_count):
            jitter_bytes = self.rng.randint(-int(per_chunk * 0.1), int(per_chunk * 0.1))
            self.add_event(
                t, "ALLOW", insider_host_ip, port, exfil_dst_ip, 443,
                bytes_out=per_chunk + jitter_bytes, bytes_in=self.rng.randint(2_000, 8_000),
                is_attack=True,
            )
            t += timedelta(seconds=self.rng.uniform(20, 90))
            port += 1
        return t

    def sorted_entries(self):
        return sorted(self.entries, key=lambda e: e["timestamp"])

    def render_text(self) -> str:
        lines = []
        for e in self.sorted_entries():
            ts = datetime.fromisoformat(e["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            lines.append(
                f"{ts} {e['host']} {e['action']} proto={e['proto']} "
                f"{e['src_ip']}:{e['src_port']} -> {e['dst_ip']}:{e['dst_port']} "
                f"bytes_out={e['bytes_out']} bytes_in={e['bytes_in']}"
            )
        return "\n".join(lines)

    def player_view(self) -> list[dict]:
        return [{k: v for k, v in e.items() if k != "is_attack"} for e in self.sorted_entries()]
