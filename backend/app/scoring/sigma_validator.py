"""
Sigma rule validator.

Parses player-submitted Sigma rules with pySigma (real parsing, real object
model) and evaluates the parsed detection logic directly against the case's
generated log entries. This is NOT a string-matching shortcut — it walks the
actual SigmaDetection/SigmaDetectionItem tree and implements Sigma's value
modifiers (contains/startswith/endswith/re/equality) and boolean condition
combination (and/or/not).

Limitations (documented, not hidden): supports flat field:value detections
and standard and/or/not condition strings. Does not implement Sigma
aggregation functions (count() by ...) or "1 of them" shorthand — out of
scope for v1.
"""
import re as _re
import fnmatch
from dataclasses import dataclass, field as dc_field

from sigma.collection import SigmaCollection
from sigma.rule import SigmaDetection, SigmaDetectionItem
from sigma.types import SigmaRegularExpression, SigmaCompareExpression
from sigma.exceptions import SigmaError

from app.core.config import MAX_RULE_BYTES


# Maps Sigma logsource categories to our internal log source keys
LOGSOURCE_CATEGORY_MAP = {
    "authentication": "auth_log",
    "dns": "dns_log",
    "firewall": "firewall_log",
    "process_creation": "process_log",
}


@dataclass
class SigmaValidationResult:
    valid_syntax: bool
    error_message: str = ""
    matched_log_source: str = ""
    matched_row_indices: list[int] = dc_field(default_factory=list)
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    attack_rows_total: int = 0


def _value_matches(field_value, sigma_value) -> bool:
    """Match a single log field value against a single parsed Sigma value."""
    if field_value is None:
        return False

    if isinstance(sigma_value, SigmaCompareExpression):
        try:
            num = float(field_value)
        except (TypeError, ValueError):
            return False
        target = float(sigma_value.number.number)
        op = sigma_value.op.name  # 'LT', 'LTE', 'GT', 'GTE'
        return {
            "LT": num < target,
            "LTE": num <= target,
            "GT": num > target,
            "GTE": num >= target,
        }.get(op, False)

    fv = str(field_value)

    if isinstance(sigma_value, SigmaRegularExpression):
        pattern = str(sigma_value.regexp)
        try:
            return bool(_re.search(pattern, fv, _re.IGNORECASE))
        except _re.error:
            return False

    pattern = str(sigma_value)
    # Sigma wildcard semantics: * and ? act as glob wildcards.
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatch(fv.lower(), pattern.lower())
    return fv.lower() == pattern.lower()


def _eval_detection_item(item: SigmaDetectionItem, log_entry: dict) -> bool:
    field_name = item.field
    if field_name is None:
        return False
    field_value = log_entry.get(field_name)

    results = [_value_matches(field_value, v) for v in item.value]
    if not results:
        return False

    # Default Sigma semantics: multiple values for one field = OR,
    # unless the 'all' modifier was used (ConditionAND linking).
    linking_name = getattr(item.value_linking, "__name__", "ConditionOR")
    if "AND" in linking_name:
        return all(results)
    return any(results)


def _eval_detection(det: SigmaDetection, log_entry: dict) -> bool:
    """Multiple items within one detection block are AND'd together
    (standard Sigma mapping semantics)."""
    if not det.detection_items:
        return False
    results = []
    for di in det.detection_items:
        if isinstance(di, SigmaDetectionItem):
            results.append(_eval_detection_item(di, log_entry))
        elif isinstance(di, SigmaDetection):
            results.append(_eval_detection(di, log_entry))
        else:
            results.append(False)
    return all(results)


def _eval_condition_string(condition: str, selection_results: dict[str, bool]) -> bool:
    """
    Safely evaluate a Sigma condition string like 'selection and not filter'
    by substituting named selections with their boolean results, then
    evaluating ONLY boolean logic (and/or/not/parentheses) — no arbitrary
    code execution.
    """
    tokens = _re.findall(r"\(|\)|\bnot\b|\band\b|\bor\b|[A-Za-z_][A-Za-z0-9_]*", condition)
    safe_parts = []
    for tok in tokens:
        low = tok.lower()
        if low in ("and", "or", "not", "(", ")"):
            safe_parts.append(low)
        elif tok in selection_results:
            safe_parts.append(str(selection_results[tok]))
        else:
            # Unknown identifier (e.g. unsupported '1 of them' shorthand) -> treat as False
            safe_parts.append("False")
    expr = " ".join(safe_parts)
    try:
        return bool(eval(expr, {"__builtins__": {}}, {}))
    except Exception:
        return False


def validate_sigma_rule(rule_yaml: str, case_logs: dict[str, list[dict]],
                         ground_truth_attack_indices: dict[str, list[int]]) -> SigmaValidationResult:
    if len(rule_yaml.encode()) > MAX_RULE_BYTES:
        return SigmaValidationResult(
            valid_syntax=False,
            error_message=f"Rule exceeds {MAX_RULE_BYTES // 1024} KB size limit."
        )
    try:
        collection = SigmaCollection.from_yaml(rule_yaml)
        rules = list(collection.rules)
        if not rules:
            return SigmaValidationResult(valid_syntax=False, error_message="No rules parsed from YAML.")
        rule = rules[0]
    except SigmaError as e:
        return SigmaValidationResult(valid_syntax=False, error_message=str(e))
    except Exception as e:
        return SigmaValidationResult(valid_syntax=False, error_message=f"Parse error: {e}")

    category = rule.logsource.category
    log_key = LOGSOURCE_CATEGORY_MAP.get(str(category) if category else "", None)
    if log_key is None or log_key not in case_logs:
        return SigmaValidationResult(
            valid_syntax=True,
            error_message=f"Rule logsource category '{category}' does not match any log source in this case.",
            matched_log_source=log_key or "",
        )

    entries = case_logs[log_key]
    attack_indices = set(ground_truth_attack_indices.get(log_key, []))

    matched_indices = []
    for idx, entry in enumerate(entries):
        selection_results = {
            name: _eval_detection(det, entry)
            for name, det in rule.detection.detections.items()
        }
        condition_str = rule.detection.condition[0] if rule.detection.condition else ""
        if _eval_condition_string(condition_str, selection_results):
            matched_indices.append(idx)

    matched_set = set(matched_indices)
    true_positives = len(matched_set & attack_indices)
    false_positives = len(matched_set - attack_indices)
    false_negatives = len(attack_indices - matched_set)

    return SigmaValidationResult(
        valid_syntax=True,
        matched_log_source=log_key,
        matched_row_indices=matched_indices,
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        attack_rows_total=len(attack_indices),
    )
