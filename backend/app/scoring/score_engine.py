"""
Composite scoring engine.

Combines three real, independently-computed signals into a final score:
  - IOC accuracy   (precision/recall against ground-truth IOCs)   -> 30 pts
  - MITRE mapping   (precision/recall against ground-truth chain) -> 20 pts
  - Detection rule  (Sigma TP/FP/FN against actual log replay)    -> 40 pts
  - Speed bonus     (faster submission within a case's par time)  -> 10 pts
"""
from dataclasses import dataclass, field

from app.scoring.sigma_validator import validate_sigma_rule, SigmaValidationResult
from app.scoring.yara_validator import validate_yara_rule, YaraValidationResult
from app.scenarios.scenario_base import GroundTruth


def _set_prf(submitted: list[str], truth: list[str]) -> tuple[float, float, float]:
    """Returns (precision, recall, f1) for case-insensitive set comparison."""
    sub = {s.strip().lower() for s in submitted if s.strip()}
    tru = {t.strip().lower() for t in truth}
    if not sub and not tru:
        return 1.0, 1.0, 1.0
    if not sub:
        return 0.0, 0.0, 0.0
    tp = len(sub & tru)
    precision = tp / len(sub) if sub else 0.0
    recall = tp / len(tru) if tru else 0.0
    f1 = 0.0 if (precision + recall) == 0 else 2 * precision * recall / (precision + recall)
    return precision, recall, f1


@dataclass
class ScoreBreakdown:
    score_ioc: float
    score_mitre: float
    score_detection: float
    score_speed_bonus: float
    score_total: float
    ioc_precision: float
    ioc_recall: float
    mitre_precision: float
    mitre_recall: float
    sigma_result: SigmaValidationResult
    yara_result: YaraValidationResult | None = None
    notes: list[str] = field(default_factory=list)


def compute_score(
    submitted_ips: list[str],
    submitted_usernames: list[str],
    submitted_mitre_ids: list[str],
    sigma_rule_yaml: str,
    ground_truth: GroundTruth,
    case_logs: dict[str, list[dict]],
    elapsed_seconds: float,
    par_seconds: float,
    yara_rule_text: str = "",
    case_samples: dict[str, str] | None = None,
) -> ScoreBreakdown:
    notes = []
    case_samples = case_samples or {}
    has_samples = bool(ground_truth.malicious_sample_ids)

    # --- IOC scoring (IPs + usernames combined) ---
    submitted_iocs = list(submitted_ips) + list(submitted_usernames)
    truth_iocs = list(ground_truth.ioc_ips) + list(ground_truth.ioc_usernames)
    ioc_p, ioc_r, ioc_f1 = _set_prf(submitted_iocs, truth_iocs)
    score_ioc = round(ioc_f1 * 30, 2)
    if ioc_f1 < 1.0:
        notes.append(f"IOC F1={ioc_f1:.2f} — precision {ioc_p:.2f}, recall {ioc_r:.2f}")

    # --- MITRE technique mapping scoring ---
    truth_mitre_ids = [t.technique_id for t in ground_truth.mitre_chain]
    mitre_p, mitre_r, mitre_f1 = _set_prf(submitted_mitre_ids, truth_mitre_ids)
    score_mitre = round(mitre_f1 * 20, 2)
    if mitre_f1 < 1.0:
        notes.append(f"MITRE F1={mitre_f1:.2f} — precision {mitre_p:.2f}, recall {mitre_r:.2f}")

    # --- Detection scoring: 40 pts total, split 20/20 between log-based
    # (Sigma) and file-based (YARA) detection when the case has samples;
    # otherwise the full 40 pts go to Sigma alone (log-only cases). ---
    detection_pool = 20.0 if has_samples else 40.0

    sigma_result = validate_sigma_rule(sigma_rule_yaml, case_logs, ground_truth.attack_log_indices)
    score_sigma = 0.0
    if not sigma_result.valid_syntax:
        notes.append(f"Sigma rule invalid: {sigma_result.error_message}")
    else:
        tp, fp, fn = sigma_result.true_positives, sigma_result.false_positives, sigma_result.false_negatives
        denom = tp + fp + fn
        sigma_f1 = 0.0
        if denom > 0:
            precision = tp / (tp + fp) if (tp + fp) else 0.0
            recall = tp / (tp + fn) if (tp + fn) else 0.0
            sigma_f1 = 0.0 if (precision + recall) == 0 else 2 * precision * recall / (precision + recall)
        score_sigma = round(sigma_f1 * detection_pool, 2)
        notes.append(f"Sigma (log) detection: TP={tp} FP={fp} FN={fn} (F1={sigma_f1:.2f})")

    score_yara = 0.0
    yara_result = None
    if has_samples:
        yara_result = validate_yara_rule(yara_rule_text, case_samples, ground_truth.malicious_sample_ids)
        if not yara_result.valid_syntax:
            notes.append(f"YARA rule invalid: {yara_result.error_message}")
        else:
            tp, fp, fn = yara_result.true_positives, yara_result.false_positives, yara_result.false_negatives
            denom = tp + fp + fn
            yara_f1 = 0.0
            if denom > 0:
                precision = tp / (tp + fp) if (tp + fp) else 0.0
                recall = tp / (tp + fn) if (tp + fn) else 0.0
                yara_f1 = 0.0 if (precision + recall) == 0 else 2 * precision * recall / (precision + recall)
            score_yara = round(yara_f1 * detection_pool, 2)
            notes.append(f"YARA (file) detection: TP={tp} FP={fp} FN={fn} (F1={yara_f1:.2f})")

    score_detection = round(score_sigma + score_yara, 2)

    # --- Speed bonus: full 10 pts at/under par, linearly decaying to 0 at 3x par ---
    if elapsed_seconds <= par_seconds:
        score_speed_bonus = 10.0
    elif elapsed_seconds >= par_seconds * 3:
        score_speed_bonus = 0.0
    else:
        frac = 1 - ((elapsed_seconds - par_seconds) / (par_seconds * 2))
        score_speed_bonus = round(max(0.0, frac) * 10, 2)

    total = round(score_ioc + score_mitre + score_detection + score_speed_bonus, 2)

    return ScoreBreakdown(
        score_ioc=score_ioc,
        score_mitre=score_mitre,
        score_detection=score_detection,
        score_speed_bonus=score_speed_bonus,
        score_total=total,
        ioc_precision=round(ioc_p, 2),
        ioc_recall=round(ioc_r, 2),
        mitre_precision=round(mitre_p, 2),
        mitre_recall=round(mitre_r, 2),
        sigma_result=sigma_result,
        yara_result=yara_result,
        notes=notes,
    )
