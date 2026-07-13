"""
Case 001 — Tier 1: SSH Brute Force

Single log source (auth log). Player must spot a brute-force credential
attack against a privileged account from an external IP amid normal
employee login noise, identify the attacker IP and compromised username,
and submit a Sigma rule that flags the attack pattern without false-
positiving on the legitimate logins.
"""
from datetime import datetime

from app.scenarios.scenario_base import BaseScenario, GroundTruth, MitreTechnique
from app.generators.auth_log_gen import AuthLogGenerator


class Case001BruteForce(BaseScenario):
    case_id = "case-001"
    title = "Midnight Knock"
    difficulty = 1
    log_sources = ["auth_log"]
    briefing = (
        "WebServer01 handles customer billing data for a mid-size logistics firm. "
        "The on-call admin noticed the server felt 'sluggish' overnight and asked "
        "you to review the last 24 hours of SSH authentication activity before "
        "the next shift starts. Determine whether anything malicious occurred, "
        "identify the source, and submit a detection rule that would catch this "
        "pattern in the future."
    )

    def generate(self):
        gen = AuthLogGenerator(seed=self.seed, hostname="webserver01")
        gen.generate_benign_traffic(count=60, time_window_hours=24)

        attacker_ip = "198.51.100.23"
        target_user = "admin"
        attack_start = gen.base_time.replace(hour=3, minute=14, second=2)
        gen.inject_brute_force_attack(
            target_username=target_user,
            attacker_ip=attacker_ip,
            start_time=attack_start,
            attempt_count=47,
            succeed=True,
        )

        self.player_logs["auth_log"] = gen.player_view()
        self.raw_text_logs["auth_log"] = gen.render_syslog()

        attack_indices = [
            i for i, e in enumerate(gen.sorted_entries()) if e["is_attack"]
        ]

        self.ground_truth = GroundTruth(
            ioc_ips=[attacker_ip],
            ioc_usernames=[target_user],
            attack_log_indices={"auth_log": attack_indices},
            mitre_chain=[
                MitreTechnique("T1110", "Brute Force", "Credential Access"),
                MitreTechnique("T1110.001", "Password Guessing", "Credential Access"),
                MitreTechnique("T1078", "Valid Accounts", "Defense Evasion, Persistence, Privilege Escalation, Initial Access"),
            ],
        )
