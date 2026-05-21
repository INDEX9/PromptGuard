from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal, Optional

from .config import DEFAULT_CONFIG, AdapterResult, ScanConfig
from .core import scan_text
from .types import DetectionReport


Decision = Literal["approve", "block", "review"]


@dataclass(frozen=True)
class ReviewDecision:
    decision: Decision
    reason: str
    report: DetectionReport
    reviewer_result: Optional[AdapterResult] = None


def review_text_write(text: str, config: ScanConfig = DEFAULT_CONFIG) -> ReviewDecision:
    # Reviewer needs evidence to make a decision; the returned report is stripped.
    full_report = scan_text(text, include_evidence=True, config=config)
    stripped_report = _strip_evidence(full_report)
    if not (full_report.is_prompt_injection or full_report.has_pii or full_report.is_contradictory):
        return ReviewDecision("approve", "No configured detector crossed its threshold.", stripped_report)
    if config.reviewer_adapter is None:
        return ReviewDecision(
            "review",
            "Local scan crossed a threshold; no reviewer adapter is configured.",
            stripped_report,
        )
    reviewer_result = config.reviewer_adapter(text, full_report)
    block_threshold = config.thresholds.reviewer_block
    if reviewer_result.score >= block_threshold:
        return ReviewDecision("block", reviewer_result.label, stripped_report, reviewer_result)
    return ReviewDecision("approve", reviewer_result.label, stripped_report, reviewer_result)


async def review_text_write_async(text: str, config: ScanConfig = DEFAULT_CONFIG) -> ReviewDecision:
    full_report = scan_text(text, include_evidence=True, config=config)
    stripped_report = _strip_evidence(full_report)
    if not (full_report.is_prompt_injection or full_report.has_pii or full_report.is_contradictory):
        return ReviewDecision("approve", "No configured detector crossed its threshold.", stripped_report)
    reviewer_result: Optional[AdapterResult] = None
    if config.async_reviewer_adapter is not None:
        reviewer_result = await config.async_reviewer_adapter(text, full_report)
    elif config.reviewer_adapter is not None:
        reviewer_result = config.reviewer_adapter(text, full_report)
    if reviewer_result is None:
        return ReviewDecision(
            "review",
            "Local scan crossed a threshold; no reviewer adapter is configured.",
            stripped_report,
        )
    block_threshold = config.thresholds.reviewer_block
    if reviewer_result.score >= block_threshold:
        return ReviewDecision("block", reviewer_result.label, stripped_report, reviewer_result)
    return ReviewDecision("approve", reviewer_result.label, stripped_report, reviewer_result)


def _strip_evidence(report: DetectionReport) -> DetectionReport:
    return replace(
        report,
        prompt_injection_findings=[replace(f, evidence="") for f in report.prompt_injection_findings],
        pii_findings=[replace(f, evidence="") for f in report.pii_findings],
        contradictions=[replace(item, positive="", negative="") for item in report.contradictions],
    )
