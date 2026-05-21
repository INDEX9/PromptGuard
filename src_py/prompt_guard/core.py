from __future__ import annotations

from dataclasses import replace
from typing import Iterable, List, Tuple

from .contradiction import detect_contradictions
from .config import DEFAULT_CONFIG, ScanConfig
from .injection import detect_prompt_injection, detect_prompt_injection_async
from .pii import detect_pii
from .types import Contradiction, DetectionReport, Finding


def scan_text(text: str, include_evidence: bool = True, config: ScanConfig = DEFAULT_CONFIG) -> DetectionReport:
    injection_score, injection_findings = detect_prompt_injection(text, config=config)
    return _build_report(text, include_evidence, config, injection_score, injection_findings)


async def scan_text_async(
    text: str, include_evidence: bool = True, config: ScanConfig = DEFAULT_CONFIG
) -> DetectionReport:
    injection_score, injection_findings = await detect_prompt_injection_async(text, config=config)
    return _build_report(text, include_evidence, config, injection_score, injection_findings)


def scan_many(
    texts: Iterable[str], include_evidence: bool = True, config: ScanConfig = DEFAULT_CONFIG
) -> List[DetectionReport]:
    """Scan an iterable of text snippets and return one report per input."""
    return [scan_text(text, include_evidence=include_evidence, config=config) for text in texts]


def _build_report(
    text: str,
    include_evidence: bool,
    config: ScanConfig,
    injection_score: float,
    injection_findings: List[Finding],
) -> DetectionReport:
    pii_score, pii_findings = detect_pii(text, config=config)
    if config.enable_contradictions:
        contradiction_score, contradictions = detect_contradictions(text)
    else:
        contradiction_score, contradictions = 0.0, []
    if not include_evidence:
        injection_findings = [_without_evidence(finding) for finding in injection_findings]
        pii_findings = [_without_evidence(finding) for finding in pii_findings]
        contradictions = [
            replace(item, positive="", negative="") for item in contradictions
        ]
    return DetectionReport(
        text=text,
        prompt_injection_score=injection_score,
        pii_score=pii_score,
        contradiction_score=contradiction_score,
        prompt_injection_findings=injection_findings,
        pii_findings=pii_findings,
        contradictions=contradictions,
        thresholds=config.thresholds,
    )


def _without_evidence(finding: Finding) -> Finding:
    return replace(finding, evidence="")
