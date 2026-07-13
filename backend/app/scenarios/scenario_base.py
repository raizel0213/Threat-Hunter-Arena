"""
Base class for Threat Hunter Arena cases (scenarios).

Each scenario is responsible for:
  - generating its own logs deterministically from a seed
  - declaring ground-truth IOCs and MITRE technique mapping (never sent to player)
  - exposing a player-safe view of the logs
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class MitreTechnique:
    technique_id: str   # e.g. "T1110"
    name: str            # e.g. "Brute Force"
    tactic: str           # e.g. "Credential Access"


@dataclass
class GroundTruth:
    ioc_ips: list[str] = field(default_factory=list)
    ioc_usernames: list[str] = field(default_factory=list)
    ioc_domains: list[str] = field(default_factory=list)
    ioc_hashes: list[str] = field(default_factory=list)
    mitre_chain: list[MitreTechnique] = field(default_factory=list)
    attack_log_indices: dict = field(default_factory=dict)  # source -> list[int] of attack rows
    malicious_sample_ids: list[str] = field(default_factory=list)  # filenames that are malicious, for YARA scoring


class BaseScenario(ABC):
    case_id: str
    title: str
    briefing: str
    difficulty: int  # 1, 2, or 3
    log_sources: list[str]

    def __init__(self, seed: int = 1337):
        self.seed = seed
        self._generated = False
        self.ground_truth = GroundTruth()
        self.player_logs: dict[str, list[dict]] = {}
        self.raw_text_logs: dict[str, str] = {}
        self.samples: dict[str, str] = {}  # filename -> recovered file content, for YARA-scoreable cases

    @abstractmethod
    def generate(self):
        """Populate self.player_logs, self.raw_text_logs, and self.ground_truth."""
        raise NotImplementedError

    def ensure_generated(self):
        if not self._generated:
            self.generate()
            self._generated = True

    def to_case_summary(self) -> dict:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "difficulty": self.difficulty,
            "log_sources": self.log_sources,
        }

    def to_case_detail(self) -> dict:
        """Player-facing view: briefing + logs + samples, NO ground truth."""
        self.ensure_generated()
        return {
            "case_id": self.case_id,
            "title": self.title,
            "difficulty": self.difficulty,
            "briefing": self.briefing,
            "log_sources": self.log_sources,
            "logs": self.player_logs,
            "raw_logs": self.raw_text_logs,
            "samples": self.samples,
        }
