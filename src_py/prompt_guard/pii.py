from __future__ import annotations

import re
from enum import Enum
from typing import Iterable, List, Optional, Pattern, Tuple

from .config import DEFAULT_CONFIG, CustomRule, ScanConfig
from .injection import _canonicalize_text, detect_prompt_injection
from .types import Finding


Rule = Tuple[str, Pattern[str], float, str]


class RedactionStrategy(str, Enum):
    FULL = "full"
    PARTIAL = "partial"
    TYPE_LABEL = "type_label"


PII_RULES: Tuple[Rule, ...] = (
    ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), 0.5, "global"),
    ("phone_us", re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\d)"), 0.45, "us"),
    ("credit_card", re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)"), 0.45, "global"),
    ("ssn_us", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0.6, "us"),
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), 0.3, "global"),
    ("api_key_like", re.compile(r"\b(?:sk|pk|api|key|token|secret)[-_]?[A-Za-z0-9_]{16,}\b"), 0.55, "global"),
    ("address_like", re.compile(r"\b\d{1,6}\s+[A-Z][A-Za-z0-9.\s]{2,60}\s+(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Lane|Ln|Drive|Dr)\b"), 0.35, "us"),
    ("phone_cn", re.compile(r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)"), 0.45, "cn"),
    ("national_id_cn", re.compile(r"(?<!\d)\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)"), 0.55, "cn"),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", re.IGNORECASE), 0.5, "eu"),
)


def detect_pii(text: str, config: ScanConfig = DEFAULT_CONFIG) -> Tuple[float, List[Finding]]:
    canonical, raw_offsets = _canonicalize_text(text)
    findings = list(_iter_findings(canonical, _configured_rules(config), "pii", raw_offsets))
    findings = [finding for finding in findings if _is_valid_finding(finding)]
    if not findings:
        return 0.0, []

    score = 1.0
    miss_product = 1.0
    for finding in findings:
        miss_product *= max(0.0, 1.0 - finding.score)
    score -= miss_product
    if len(findings) >= 2:
        score = min(1.0, score + 0.1)
    return round(score, 3), findings


def redact_pii(
    text: str,
    replacement: str = "[REDACTED]",
    config: ScanConfig = DEFAULT_CONFIG,
    strategy: str = RedactionStrategy.FULL.value,
) -> str:
    """Redact detected PII spans only."""
    return _redact_spans(text, detect_pii(text, config=config)[1], replacement, strategy)


def redact_text(
    text: str,
    replacement: str = "[REDACTED]",
    config: ScanConfig = DEFAULT_CONFIG,
    strategy: str = RedactionStrategy.FULL.value,
) -> str:
    """Redact both PII and prompt-injection spans.

    Findings without resolvable offsets (e.g. classifier-adapter findings with
    start/end of -1) are skipped because there is no span to replace.
    """
    pii_findings = detect_pii(text, config=config)[1]
    injection_findings = detect_prompt_injection(text, config=config)[1]
    return _redact_spans(text, list(pii_findings) + list(injection_findings), replacement, strategy)


def _redact_spans(text: str, findings: List[Finding], replacement: str, strategy: str) -> str:
    spans = [(f.start, f.end, f) for f in findings if f.start >= 0 and f.end > f.start]
    if not spans:
        return text
    spans.sort(key=lambda item: (item[0], -item[1]))
    merged: List[Tuple[int, int, Finding]] = []
    for start, end, finding in spans:
        if merged and start < merged[-1][1]:
            prev_start, prev_end, prev_finding = merged[-1]
            keep = finding if finding.score > prev_finding.score else prev_finding
            merged[-1] = (prev_start, max(prev_end, end), keep)
        else:
            merged.append((start, end, finding))
    redacted = text
    for start, end, finding in reversed(merged):
        value = _redaction_value(text[start:end], finding.label, replacement, strategy)
        redacted = redacted[:start] + value + redacted[end:]
    return redacted


def _configured_rules(config: ScanConfig) -> Tuple[Rule, ...]:
    active_locales = set(config.pii_locales) | {"global"}
    builtin_rules = [rule for rule in PII_RULES if rule[3] in active_locales]
    if config.enabled_rules is not None:
        builtin_labels = {rule[0] for rule in builtin_rules}
        if config.enabled_rules & builtin_labels:
            builtin_rules = [rule for rule in builtin_rules if rule[0] in config.enabled_rules]
    extra_rules: List[Rule] = []
    for item in config.extra_rules:
        if item.kind != "pii":
            continue
        extra_rules.append((item.label, re.compile(item.pattern, _rule_flags(item)), item.score, "custom"))
    rules = builtin_rules + extra_rules
    if config.disabled_rules:
        rules = [rule for rule in rules if rule[0] not in config.disabled_rules]
    return tuple(rules)


def _rule_flags(rule: CustomRule) -> int:
    flags = 0
    if not rule.case_sensitive:
        flags |= re.IGNORECASE
    if rule.dotall:
        flags |= re.DOTALL
    return flags


def _iter_findings(
    text: str,
    rules: Iterable[Rule],
    kind: str,
    raw_offsets: Optional[List[int]] = None,
) -> Iterable[Finding]:
    for label, pattern, score, _locale in rules:
        for match in pattern.finditer(text):
            start, end = match.start(), match.end()
            if raw_offsets is not None:
                start = raw_offsets[start]
                end = raw_offsets[end]
            yield Finding.create(
                kind=kind,
                label=label,
                evidence=match.group(0).strip(),
                start=start,
                end=end,
                score=score,
            )


def _is_valid_finding(finding: Finding) -> bool:
    if finding.label == "credit_card":
        digits = re.sub(r"\D", "", finding.evidence)
        return 13 <= len(digits) <= 19 and _luhn_valid(digits)
    if finding.label == "national_id_cn":
        return _china_id_valid(finding.evidence)
    if finding.label == "iban":
        return _iban_valid(finding.evidence)
    return True


def _luhn_valid(digits: str) -> bool:
    checksum = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        value = int(char)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        checksum += value
    return checksum % 10 == 0


def _china_id_valid(value: str) -> bool:
    digits = value.upper()
    if len(digits) != 18:
        return False
    weights = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    checks = "10X98765432"
    try:
        total = sum(int(digits[index]) * weights[index] for index in range(17))
    except ValueError:
        return False
    return checks[total % 11] == digits[-1]


def _iban_valid(value: str) -> bool:
    compact = re.sub(r"\s+", "", value).upper()
    if len(compact) < 15 or len(compact) > 34 or not re.match(r"^[A-Z]{2}\d{2}[A-Z0-9]+$", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    expanded = "".join(str(ord(char) - 55) if char.isalpha() else char for char in rearranged)
    return int(expanded) % 97 == 1


def _redaction_value(value: str, label: str, replacement: str, strategy: str) -> str:
    if strategy == RedactionStrategy.TYPE_LABEL.value:
        return f"[{label.upper()}]"
    if strategy == RedactionStrategy.PARTIAL.value:
        return _partial_mask(value)
    return replacement


def _partial_mask(value: str) -> str:
    if "@" in value:
        name, domain = value.split("@", 1)
        return f"{name[:1]}***@{domain}"
    visible = [char for char in value if char.isalnum()]
    keep = 4 if len(visible) > 8 else 2
    remaining = keep
    masked = []
    for char in reversed(value):
        if char.isalnum():
            if remaining > 0:
                masked.append(char)
                remaining -= 1
            else:
                masked.append("*")
        else:
            masked.append(char)
    return "".join(reversed(masked))
