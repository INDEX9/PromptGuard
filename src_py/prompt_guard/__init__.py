"""PromptGuard public API."""

from .core import (
    Contradiction,
    DetectionReport,
    Finding,
    scan_many,
    scan_text,
    scan_text_async,
)
from .config import AdapterResult, CustomRule, ScanConfig, Thresholds
from .contradiction import EXPERIMENTAL as _CONTRADICTION_EXPERIMENTAL
from .contradiction import detect_contradictions
from .injection import detect_prompt_injection, detect_prompt_injection_async
from .pii import detect_pii, redact_pii, redact_text
from .reviewer import ReviewDecision, review_text_write, review_text_write_async
from .types import OWASP_LLM_CATEGORIES, category_for_label, severity_for_score

EXPERIMENTAL_DETECTORS = frozenset({"contradiction"} if _CONTRADICTION_EXPERIMENTAL else ())

__all__ = [
    "Contradiction",
    "DetectionReport",
    "Finding",
    "CustomRule",
    "AdapterResult",
    "ScanConfig",
    "Thresholds",
    "EXPERIMENTAL_DETECTORS",
    "OWASP_LLM_CATEGORIES",
    "category_for_label",
    "severity_for_score",
    "detect_contradictions",
    "detect_prompt_injection",
    "detect_prompt_injection_async",
    "detect_pii",
    "redact_pii",
    "redact_text",
    "ReviewDecision",
    "review_text_write",
    "review_text_write_async",
    "scan_many",
    "scan_text",
    "scan_text_async",
]
