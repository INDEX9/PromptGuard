from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .config import Thresholds

# OWASP LLM Top 10 (2025) category for each detection label.
OWASP_LLM_CATEGORIES: Dict[str, str] = {
    "instruction_override": "LLM01",
    "role_rebinding": "LLM01",
    "secret_exfiltration": "LLM07",
    "tool_misuse": "LLM06",
    "persistence_memory_poisoning": "LLM04",
    "retrieval_poisoning": "LLM04",
    "malicious_bridging": "LLM01",
    "delimiter_smuggling": "LLM01",
    "policy_of_thought_leakage": "LLM07",
    "jailbreak_intent": "LLM01",
    "mentions_decoding_instruction": "LLM01",
    "zh_instruction_override": "LLM01",
    "zh_secret_exfiltration": "LLM07",
    "zh_memory_poisoning": "LLM04",
    "memory_write_gate": "LLM04",
    "rag_document_injection": "LLM01",
    "tool_call_policy_bypass": "LLM06",
    "decoded_payload": "LLM01",
    "email": "LLM02",
    "phone_us": "LLM02",
    "credit_card": "LLM02",
    "ssn_us": "LLM02",
    "ipv4": "LLM02",
    "api_key_like": "LLM02",
    "address_like": "LLM02",
    "phone_cn": "LLM02",
    "national_id_cn": "LLM02",
    "iban": "LLM02",
    # Secrets pack (vendor credential fingerprints).
    "aws_access_key_id": "LLM02",
    "github_token": "LLM02",
    "openai_api_key": "LLM02",
    "anthropic_api_key": "LLM02",
    "slack_token": "LLM02",
    "stripe_secret_key": "LLM02",
    "google_api_key": "LLM02",
    "jwt": "LLM02",
    "private_key_pem": "LLM02",
    "gcp_service_account": "LLM02",
    # Tool args injection (LLM06: Excessive Agency / Insecure Plugin Design).
    "sql_injection": "LLM06",
    "nosql_operator_injection": "LLM06",
    "shell_metacharacter": "LLM06",
    "path_traversal": "LLM06",
    "ssrf_metadata_url": "LLM06",
    "ssrf_private_url": "LLM06",
    "code_interpreter_primitive": "LLM06",
    "windows_command_injection": "LLM06",
    # Output-side risks (LLM07: System Prompt Leakage, LLM02: PII).
    "system_prompt_echo": "LLM07",
    "chat_template_token_leak": "LLM07",
    "internal_instruction_leak": "LLM07",
    "refusal_then_compliance": "LLM01",
    "sensitive_topic_response": "LLM01",
}

# Fallback category by detector kind for custom / unmapped labels.
_KIND_CATEGORIES: Dict[str, str] = {
    "prompt_injection": "LLM01",
    "pii": "LLM02",
    "tool_args": "LLM06",
    "output_risk": "LLM07",
}


def severity_for_score(score: float) -> str:
    """Map an aggregate-free per-finding score to a severity tier."""
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def category_for_label(label: str, kind: str) -> str:
    """Map a finding label to an OWASP LLM Top 10 category id."""
    return OWASP_LLM_CATEGORIES.get(label, _KIND_CATEGORIES.get(kind, ""))


@dataclass(frozen=True)
class Finding:
    kind: str
    label: str
    evidence: str
    start: int
    end: int
    score: float
    severity: str = "low"
    category: str = ""

    @classmethod
    def create(
        cls,
        kind: str,
        label: str,
        evidence: str,
        start: int,
        end: int,
        score: float,
    ) -> "Finding":
        """Build a finding with severity and OWASP category auto-filled."""
        return cls(
            kind=kind,
            label=label,
            evidence=evidence,
            start=start,
            end=end,
            score=score,
            severity=severity_for_score(score),
            category=category_for_label(label, kind),
        )


@dataclass(frozen=True)
class Contradiction:
    subject: str
    positive: str
    negative: str
    confidence: float


@dataclass(frozen=True)
class DetectionReport:
    text: str
    prompt_injection_score: float
    pii_score: float
    contradiction_score: float
    prompt_injection_findings: List[Finding] = field(default_factory=list)
    pii_findings: List[Finding] = field(default_factory=list)
    contradictions: List[Contradiction] = field(default_factory=list)
    thresholds: Thresholds = field(default_factory=Thresholds)

    @property
    def is_prompt_injection(self) -> bool:
        return self.prompt_injection_score >= self.thresholds.prompt_injection

    @property
    def has_pii(self) -> bool:
        return self.pii_score >= self.thresholds.pii

    @property
    def is_contradictory(self) -> bool:
        return self.contradiction_score >= self.thresholds.contradiction

    def as_dict(self) -> Dict[str, object]:
        """Return the canonical snake_case wire format shared with the TS package."""
        return {
            "text": self.text,
            "is_prompt_injection": self.is_prompt_injection,
            "has_pii": self.has_pii,
            "is_contradictory": self.is_contradictory,
            "prompt_injection_score": self.prompt_injection_score,
            "pii_score": self.pii_score,
            "contradiction_score": self.contradiction_score,
            "thresholds": {
                "prompt_injection": self.thresholds.prompt_injection,
                "pii": self.thresholds.pii,
                "contradiction": self.thresholds.contradiction,
                "reviewer_block": self.thresholds.reviewer_block,
            },
            "prompt_injection_findings": [_finding_dict(finding) for finding in self.prompt_injection_findings],
            "pii_findings": [_finding_dict(finding) for finding in self.pii_findings],
            "contradictions": [_contradiction_dict(item) for item in self.contradictions],
        }


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


def _contradiction_dict(item: Contradiction) -> Dict[str, object]:
    return {
        "subject": item.subject,
        "positive": item.positive,
        "negative": item.negative,
        "confidence": item.confidence,
    }
