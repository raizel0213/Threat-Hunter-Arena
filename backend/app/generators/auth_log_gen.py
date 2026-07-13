"""
Synthetic SSH/auth log generator.

Produces structured, schema-realistic auth log entries (modeled on Linux
sshd syslog format) and can render them as raw syslog text for the log
viewer UI. Generation is seeded so a given case always reproduces
identically for scoring purposes.
"""
import random
from datetime import datetime, timedelta
from typing import Optional

from app.core.config import COMMON_USERNAMES, ATTACKER_USERNAMES_TRIED, INTERNAL_SUBNET


class AuthLogGenerator:
    def __init__(self, seed: int, base_time: Optional[datetime] = None, hostname: str = "webserver01"):
        self.rng = random.Random(seed)
        self.base_time = base_time or datetime(2026, 6, 18, 0, 0, 0)
        self.hostname = hostname
        self._pid_counter = self.rng.randint(20000, 25000)
        self.entries: list[dict] = []

    def _next_pid(self) -> int:
        self._pid_counter += self.rng.randint(1, 4)
        return self._pid_counter

    def _internal_ip(self) -> str:
        return f"{INTERNAL_SUBNET}{self.rng.randint(2, 254)}"

    def add_event(self, timestamp: datetime, event_type: str, username: str,
                  src_ip: str, src_port: int, raw_extra: str = "", is_attack: bool = False):
        entry = {
            "timestamp": timestamp.isoformat(),
            "host": self.hostname,
            "source": "sshd",
            "pid": self._next_pid(),
            "event_type": event_type,  # failed_password | accepted_password | invalid_user
            "username": username,
            "src_ip": src_ip,
            "src_port": src_port,
            "is_attack": is_attack,  # ground truth marker, stripped before sending to player
        }
        self.entries.append(entry)
        return entry

    def generate_benign_traffic(self, count: int, time_window_hours: int = 24):
        """Scatter normal employee logins across a day."""
        for _ in range(count):
            ts = self.base_time + timedelta(
                seconds=self.rng.randint(0, time_window_hours * 3600)
            )
            user = self.rng.choice(COMMON_USERNAMES[:10])  # exclude admin/svc accounts
            ip = self._internal_ip()
            port = self.rng.randint(40000, 65000)
            # occasionally a benign typo'd failed login before success
            if self.rng.random() < 0.15:
                self.add_event(ts, "failed_password", user, ip, port)
                ts2 = ts + timedelta(seconds=self.rng.randint(2, 8))
                self.add_event(ts2, "accepted_password", user, ip, port + 1)
            else:
                self.add_event(ts, "accepted_password", user, ip, port)

    def inject_brute_force_attack(self, target_username: str, attacker_ip: str,
                                   start_time: datetime, attempt_count: int = 47,
                                   succeed: bool = True):
        """
        Inject a realistic SSH brute-force attack chain:
        many failed attempts against a target username from a single
        external IP in a tight time window, followed by a successful
        login (credential stuffing success) if `succeed` is True.
        """
        t = start_time
        tried_users = ATTACKER_USERNAMES_TRIED.copy()
        if target_username not in tried_users:
            tried_users.append(target_username)
        self.rng.shuffle(tried_users)

        port = self.rng.randint(50000, 64000)
        for i in range(attempt_count):
            user = target_username if i >= attempt_count - 5 else self.rng.choice(tried_users)
            event_type = "failed_password"
            self.add_event(t, event_type, user, attacker_ip, port, is_attack=True)
            t += timedelta(seconds=self.rng.uniform(1.0, 3.5))
            port += 1

        if succeed:
            t += timedelta(seconds=self.rng.uniform(2.0, 6.0))
            self.add_event(t, "accepted_password", target_username, attacker_ip, port, is_attack=True)

        return t  # return end time so scenario can chain further events

    def sorted_entries(self):
        return sorted(self.entries, key=lambda e: e["timestamp"])

    def render_syslog(self) -> str:
        """Render entries as raw syslog-style text, like a real /var/log/auth.log."""
        lines = []
        for e in self.sorted_entries():
            ts = datetime.fromisoformat(e["timestamp"]).strftime("%b %d %H:%M:%S")
            if e["event_type"] == "failed_password":
                lines.append(
                    f"{ts} {e['host']} sshd[{e['pid']}]: Failed password for "
                    f"{'invalid user ' if e['username'] not in COMMON_USERNAMES else ''}"
                    f"{e['username']} from {e['src_ip']} port {e['src_port']} ssh2"
                )
            elif e["event_type"] == "accepted_password":
                lines.append(
                    f"{ts} {e['host']} sshd[{e['pid']}]: Accepted password for "
                    f"{e['username']} from {e['src_ip']} port {e['src_port']} ssh2"
                )
        return "\n".join(lines)

    def player_view(self) -> list[dict]:
        """Strip ground-truth markers before sending logs to the player."""
        return [
            {k: v for k, v in e.items() if k != "is_attack"}
            for e in self.sorted_entries()
        ]
