"""
YARA rule validator with execution timeout and rule size limit.

Compiles player-submitted YARA rules with yara-python and runs matching
against case sample artifacts. Wrapped in a thread-pool executor with a
hard timeout so a pathological regex rule cannot hang the process.
"""
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
import logging

import yara

from app.core.config import YARA_TIMEOUT_SECONDS, MAX_RULE_BYTES

log = logging.getLogger(__name__)
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="yara")


@dataclass
class YaraValidationResult:
    valid_syntax: bool
    error_message: str = ""
    matched_sample_ids: list[str] = field(default_factory=list)
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    malicious_total: int = 0


def _compile_and_match(rule_source: str, samples: dict[str, bytes]) -> tuple[list[str], None] | tuple[None, str]:
    """Run inside executor thread — separated so we can time it out."""
    try:
        compiled = yara.compile(source=rule_source)
    except yara.SyntaxError as e:
        return None, f"Syntax error: {e}"
    except yara.Error as e:
        return None, f"YARA error: {e}"

    matched = []
    for sample_id, content in samples.items():
        data = content if isinstance(content, bytes) else content.encode("utf-8", errors="ignore")
        try:
            if compiled.match(data=data):
                matched.append(sample_id)
        except yara.Error as e:
            return None, f"Match error on '{sample_id}': {e}"
    return matched, None


def validate_yara_rule(
    rule_source: str,
    samples: dict[str, str],
    malicious_sample_ids: list[str],
) -> YaraValidationResult:
    if not rule_source.strip():
        return YaraValidationResult(valid_syntax=False, error_message="No YARA rule submitted.")

    if len(rule_source.encode()) > MAX_RULE_BYTES:
        return YaraValidationResult(
            valid_syntax=False,
            error_message=f"Rule exceeds {MAX_RULE_BYTES // 1024} KB size limit."
        )

    byte_samples = {
        k: v.encode("utf-8", errors="ignore") if isinstance(v, str) else v
        for k, v in samples.items()
    }

    future = _executor.submit(_compile_and_match, rule_source, byte_samples)
    try:
        matched_ids, err = future.result(timeout=YARA_TIMEOUT_SECONDS)
    except FuturesTimeout:
        future.cancel()
        log.warning("YARA execution timed out after %ds", YARA_TIMEOUT_SECONDS)
        return YaraValidationResult(
            valid_syntax=True,
            error_message=f"Rule execution timed out after {YARA_TIMEOUT_SECONDS}s. "
                          "Simplify your rule conditions."
        )
    except Exception as e:
        return YaraValidationResult(valid_syntax=False, error_message=str(e))

    if err:
        return YaraValidationResult(valid_syntax=False, error_message=err)

    malicious_set = set(malicious_sample_ids)
    matched_set = set(matched_ids)
    return YaraValidationResult(
        valid_syntax=True,
        matched_sample_ids=matched_ids,
        true_positives=len(matched_set & malicious_set),
        false_positives=len(matched_set - malicious_set),
        false_negatives=len(malicious_set - matched_set),
        malicious_total=len(malicious_set),
    )
