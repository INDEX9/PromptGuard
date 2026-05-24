"""Output-side risk detection for LLM responses.

Concerns when scanning *what the model said* rather than *what the user
sent*: leaking the system prompt, echoing chat-template tokens, revealing
internal instructions, refusal-then-compliance jailbreak success markers,
and PII leaking out of the model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Pattern, Sequence, Tuple

from .config import DEFAULT_CONFIG, ScanConfig, Thresholds
from .injection import _canonicalize_text
from .pii import detect_pii
from .types import Finding, category_for_label, severity_for_score


Rule = Tuple[str, Pattern[str], float]


OUTPUT_RULES: Tuple[Rule, ...] = (
    (
        "system_prompt_echo",
        re.compile(
            r"\b(?:I am|You are)\s+an?\s+(?:helpful|harmless|advanced|honest|knowledgeable)?\s*"
            r"(?:AI|artificial intelligence|assistant|language model|chatbot)\b",
            re.IGNORECASE,
        ),
        0.55,
    ),
    (
        "chat_template_token_leak",
        re.compile(
            r"(<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|assistant\|>|<\|user\|>|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>)",
        ),
        0.7,
    ),
    (
        "internal_instruction_leak",
        re.compile(
            r"\b(?:my\s+(?:system\s+)?(?:prompt|instructions?|directives?|rules?|guidelines?)\s+(?:say|state|require|are|is)|"
            r"I\s+was\s+(?:told|instructed|trained|configured)\s+to|"
            r"according\s+to\s+my\s+(?:training|instructions|system\s+prompt|developer))\b",
            re.IGNORECASE,
        ),
        0.6,
    ),
    (
        "refusal_then_compliance",
        re.compile(
            r"\b(?:I\s+(?:cannot|can'?t|won'?t|am\s+unable\s+to)|sorry,?\s+(?:but\s+)?I)\b[^.]{0,200}\b"
            r"(?:however|but|that\s+said|on\s+the\s+other\s+hand|alternatively)\b[^.]{0,200}\b"
            r"(?:here(?:'s|\s+is)|step\s+\d+|first[,:]|sure[,!])\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.6,
    ),
    (
        "sensitive_topic_response",
        re.compile(
            r"\b(?:step\s+\d+\s*:?\s*(?:acquire|obtain|synthesize|build|construct)|"
            r"here(?:'s|\s+is)\s+how\s+to\s+(?:make|build|synthesize|hack|exploit|bypass))\b",
            re.IGNORECASE,
        ),
        0.55,
    ),
)


@dataclass(frozen=True)
class OutputReport:
    text: str
    output_risk_score: float
    pii_score: float
    output_risk_findings: List[Finding] = field(default_factory=list)
    pii_findings: List[Finding] = field(default_factory=list)
    thresholds: Thresholds = field(default_factory=Thresholds)

    @property
    def is_output_risk(self) -> bool:
        return self.output_risk_score >= self.thresholds.output_risk

    @property
    def has_pii(self) -> bool:
        return self.pii_score >= self.thresholds.pii

    def as_dict(self) -> Dict[str, object]:
        return {
            "text": self.text,
            "is_output_risk": self.is_output_risk,
            "has_pii": self.has_pii,
            "output_risk_score": self.output_risk_score,
            "pii_score": self.pii_score,
            "thresholds": {
                "output_risk": self.thresholds.output_risk,
                "pii": self.thresholds.pii,
            },
            "output_risk_findings": [_finding_dict(f) for f in self.output_risk_findings],
            "pii_findings": [_finding_dict(f) for f in self.pii_findings],
        }


def detect_output_risk(text: str, config: ScanConfig = DEFAULT_CONFIG) -> Tuple[float, List[Finding]]:
    canonical, raw_offsets = _canonicalize_text(text)
    findings: List[Finding] = []
    for label, pattern, score in _configured_rules(config):
        for match in pattern.finditer(canonical):
            start = raw_offsets[match.start()]
            end = raw_offsets[match.end()]
            findings.append(
                Finding(
                    kind="output_risk",
                    label=label,
                    evidence=match.group(0).strip(),
                    start=start,
                    end=end,
                    score=score,
                    severity=severity_for_score(score),
                    category=category_for_label(label, "output_risk"),
                )
            )
    return _aggregate(findings), findings


def scan_output(text: str, include_evidence: bool = True, config: ScanConfig = DEFAULT_CONFIG) -> OutputReport:
    output_score, output_findings = detect_output_risk(text, config=config)
    pii_score, pii_findings = detect_pii(text, config=config)
    if not include_evidence:
        output_findings = [_strip_evidence(f) for f in output_findings]
        pii_findings = [_strip_evidence(f) for f in pii_findings]
    return OutputReport(
        text=text,
        output_risk_score=output_score,
        pii_score=pii_score,
        output_risk_findings=output_findings,
        pii_findings=pii_findings,
        thresholds=config.thresholds,
    )


def _configured_rules(config: ScanConfig) -> Iterable[Rule]:
    rules: List[Rule] = list(OUTPUT_RULES)
    for item in config.extra_rules:
        if item.kind != "output_risk":
            continue
        flags = 0
        if not item.case_sensitive:
            flags |= re.IGNORECASE
        if item.dotall:
            flags |= re.DOTALL
        rules.append((item.label, re.compile(item.pattern, flags), item.score))
    if config.enabled_rules is not None:
        builtin_labels = {label for label, _, _ in OUTPUT_RULES}
        if config.enabled_rules & builtin_labels:
            rules = [r for r in rules if r[0] in config.enabled_rules or r[0] not in builtin_labels]
    if config.disabled_rules:
        rules = [r for r in rules if r[0] not in config.disabled_rules]
    return rules


def _aggregate(findings: Sequence[Finding]) -> float:
    if not findings:
        return 0.0
    miss = 1.0
    for f in findings:
        miss *= max(0.0, 1.0 - f.score)
    score = 1.0 - miss
    if len(findings) >= 2:
        score = min(1.0, score + 0.1)
    return round(score, 3)


def _strip_evidence(finding: Finding) -> Finding:
    return Finding(
        kind=finding.kind,
        label=finding.label,
        evidence="",
        start=finding.start,
        end=finding.end,
        score=finding.score,
        severity=finding.severity,
        category=finding.category,
    )


def _finding_dict(finding: Finding) -> Dict[str, object]:
    return {
        "kind": finding.kind,
        "label": finding.label,
        "evidence": finding.evidence,
        "start": finding.start,
        "end": finding.end,
        "score": finding.score,
        "severity": finding.severity,
        "category": finding.category,
    }
