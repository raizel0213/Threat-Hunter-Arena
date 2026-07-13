"""
Case 003 — Tier 3: Insider Threat — Staging & Exfiltration

Multi-source case (process + DNS + firewall logs) with deliberately heavy
benign noise to create a realistic low signal-to-noise ratio. Player must
find a single employee archiving sensitive HR data, resolving a personal
cloud-storage domain, then exfiltrating a large volume of data over HTTPS
in chunked transfers during off-hours — among hundreds of ordinary
employee log lines.
"""
from datetime import datetime

from app.scenarios.scenario_base import BaseScenario, GroundTruth, MitreTechnique
from app.generators.process_log_gen import ProcessLogGenerator, BENIGN_PROCESS_TREES
from app.generators.dns_log_gen import DnsLogGenerator
from app.generators.firewall_log_gen import FirewallLogGenerator
from app.core.config import INTERNAL_SUBNET


class Case003InsiderExfil(BaseScenario):
    case_id = "case-003"
    title = "Quiet Resignation"
    difficulty = 3
    log_sources = ["process_log", "dns_log", "firewall_log"]
    briefing = (
        "An HR employee submitted their two-weeks notice yesterday afternoon. "
        "Standard policy requires a review of their activity over their final "
        "two weeks before offboarding. You have process creation logs from "
        "their workstation, DNS query logs, and firewall connection logs for "
        "the full company network — hundreds of ordinary employee log lines "
        "are mixed in with whatever did or didn't happen. Determine whether "
        "this departure is routine or whether company data left the building."
    )

    def generate(self):
        insider_user = "rkapoor"
        insider_host_ip = f"{INTERNAL_SUBNET}91"
        exfil_domain = "send-files-anon24.mega.nz"
        exfil_dst_ip = "185.230.63.171"
        archive_name = "HR_Compensation_Review_2026.7z"

        # --- Process log: heavy benign noise + staging activity ---
        proc_gen = ProcessLogGenerator(seed=self.seed, hostname="ws-hr-022")
        proc_gen.generate_benign_traffic(count=140, time_window_hours=72)

        staging_time = proc_gen.base_time.replace(hour=22, minute=10, second=0)
        proc_gen.add_event(
            staging_time, "ws-hr-022", "explorer.exe", "7z.exe",
            f'7z.exe a -p -mhe=on "C:\\Users\\rkapoor\\Downloads\\{archive_name}" '
            f'"\\\\hr-share01\\Compensation\\*"',
            insider_user, is_attack=True,
        )

        # --- DNS log: heavy benign noise + single lookup of exfil domain ---
        dns_gen = DnsLogGenerator(seed=self.seed, resolver_host="dns-internal01")
        dns_gen.generate_benign_traffic(count=300, time_window_hours=72)
        dns_lookup_time = staging_time.replace(hour=22, minute=34, second=12)
        dns_gen.add_event(
            dns_lookup_time, insider_host_ip, exfil_domain, "A", exfil_dst_ip, is_attack=True,
        )

        # --- Firewall log: heavy benign noise + chunked off-hours exfil ---
        fw_gen = FirewallLogGenerator(seed=self.seed, firewall_host="fw-edge01")
        fw_gen.generate_benign_traffic(count=400, time_window_hours=72)
        exfil_start = dns_lookup_time.replace(hour=22, minute=36, second=0)
        fw_gen.inject_exfiltration(
            insider_host_ip=insider_host_ip,
            exfil_dst_ip=exfil_dst_ip,
            start_time=exfil_start,
            total_bytes_out=480_000_000,
            chunk_count=6,
        )

        # --- Assemble player views ---
        self.player_logs["process_log"] = proc_gen.player_view()
        self.player_logs["dns_log"] = dns_gen.player_view()
        self.player_logs["firewall_log"] = fw_gen.player_view()

        self.raw_text_logs["process_log"] = proc_gen.render_text()
        self.raw_text_logs["dns_log"] = dns_gen.render_text()
        self.raw_text_logs["firewall_log"] = fw_gen.render_text()

        process_attack_idx = [i for i, e in enumerate(proc_gen.sorted_entries()) if e["is_attack"]]
        dns_attack_idx = [i for i, e in enumerate(dns_gen.sorted_entries()) if e["is_attack"]]
        fw_attack_idx = [i for i, e in enumerate(fw_gen.sorted_entries()) if e["is_attack"]]

        self.ground_truth = GroundTruth(
            ioc_ips=[insider_host_ip, exfil_dst_ip],
            ioc_usernames=[insider_user],
            ioc_domains=[exfil_domain],
            attack_log_indices={
                "process_log": process_attack_idx,
                "dns_log": dns_attack_idx,
                "firewall_log": fw_attack_idx,
            },
            mitre_chain=[
                MitreTechnique("T1560.001", "Archive via Utility", "Collection"),
                MitreTechnique("T1005", "Data from Local System", "Collection"),
                MitreTechnique("T1567.002", "Exfiltration to Cloud Storage", "Exfiltration"),
            ],
        )
