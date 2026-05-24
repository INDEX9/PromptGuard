"""Detect injection patterns in agent tool / function call arguments.

Unlike free-text prompt injection, tool args are usually structured
(`dict[str, Any]`) and the threats are concrete: SQL/NoSQL injection,
shell metacharacters, path traversal, SSRF to cloud metadata endpoints,
and code-interpreter primitives. This module walks the args recursively
and scans every string value with a dedicated rule set.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, List, Mapping, Pattern, Sequence, Tuple

from .config import DEFAULT_CONFIG, ScanConfig, Thresholds
from .types import Finding, category_for_label, severity_for_score


Rule = Tuple[str, Pattern[str], float]


TOOL_ARGS_RULES: Tuple[Rule, ...] = (
    (
        "sql_injection",
        re.compile(
            r"('\s*or\s*'?\d|\bunion\s+select\b|\bdrop\s+table\b|\b(?:or|and)\s+\d+\s*=\s*\d+\b|--(?:\s|$)|/\*.*?\*/|;\s*--)",
            re.IGNORECASE | re.DOTALL,
        ),
        0.7,
    ),
    (
        "nosql_operator_injection",
        re.compile(r'(?<![A-Za-z])\$(?:where|ne|gt|gte|lt|lte|regex|in|nin|exists|expr)\b'),
        0.6,
    ),
    (
        "shell_metacharacter",
        re.compile(r"(`[^`]+`|\$\([^)]+\)|\|\s*(?:bash|sh|zsh|nc|curl|wget|python|perl|ruby)\b|;\s*(?:rm|curl|wget|nc|bash|sh)\s)"),
        0.7,
    ),
    (
        "path_traversal",
        re.compile(r"(?:\.\./|\.\.\\){2,}|(?:^|/)etc/(?:passwd|shadow)\b|(?:^|\\)windows\\system32\b", re.IGNORECASE),
        0.7,
    ),
    (
        "ssrf_metadata_url",
        re.compile(
            r"\bhttps?://(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|fd00:ec2::254)\b",
            re.IGNORECASE,
        ),
        0.85,
    ),
    (
        "ssrf_private_url",
        re.compile(
            r"\bhttps?://(?:127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)",
            re.IGNORECASE,
        ),
        0.6,
    ),
    (
        "code_interpreter_primitive",
        re.compile(
            r"\b(?:import\s+(?:os|subprocess|socket|requests)\b|__import__\s*\(|subprocess\.|os\.system\s*\(|eval\s*\(|exec\s*\(|compile\s*\()",
            re.IGNORECASE,
        ),
        0.7,
    ),
    (
        "windows_command_injection",
        re.compile(r"(?:^|[&|;])\s*(?:cmd|powershell|wmic|reg|net)\.?(?:exe)?\s+", re.IGNORECASE),
        0.65,
    ),
)


@dataclass(frozen=True)
class ToolArgsReport:
    args: Any
    tool_args_score: float
    tool_args_findings: List[Finding] = field(default_factory=list)
    thresholds: Thresholds = field(default_factory=Thresholds)

    @property
    def is_tool_args_injection(self) -> bool:
        return self.tool_args_score >= self.thresholds.tool_args

    def as_dict(self) -> dict:
        return {
            "is_tool_args_injection": self.is_tool_args_injection,
            "tool_args_score": self.tool_args_score,
            "tool_args_findings": [
                {
                    "kind": f.kind,
                    "label": f.label,
                    "evidence": f.evidence,
                    "path": _path_from_evidence_id(f),
                    "score": f.score,
                    "severity": f.severity,
                    "category": f.category,
                }
                for f in self.tool_args_findings
            ],
            "thresholds": {
                "tool_args": self.thresholds.tool_args,
            },
        }


def detect_tool_args(args: Any, config: ScanConfig = DEFAULT_CONFIG) -> Tuple[float, List[Finding]]:
    findings: List[Finding] = []
    for path, value in _iter_string_values(args, ""):
        for label, pattern, score in _configured_rules(config):
            for match in pattern.finditer(value):
                evidence = match.group(0).strip()
                # Encode the arg path into the evidence prefix to keep the
                # Finding shape compatible with the rest of the kit.
                findings.append(
                    Finding(
                        kind="tool_args",
                        label=label,
                        evidence=f"{path}: {evidence}" if path else evidence,
                        start=-1,
                        end=-1,
                        score=score,
                        severity=severity_for_score(score),
                        category=category_for_label(label, "tool_args"),
                    )
                )
    return _aggregate(findings), findings


def scan_tool_args(args: Any, config: ScanConfig = DEFAULT_CONFIG) -> ToolArgsReport:
    score, findings = detect_tool_args(args, config=config)
    return ToolArgsReport(
        args=args,
        tool_args_score=score,
        tool_args_findings=findings,
        thresholds=config.thresholds,
    )


def _configured_rules(config: ScanConfig) -> Iterable[Rule]:
    rules = list(TOOL_ARGS_RULES)
    for item in config.extra_rules:
        if item.kind != "tool_args":
            continue
        flags = 0
        if not item.case_sensitive:
            flags |= re.IGNORECASE
        if item.dotall:
            flags |= re.DOTALL
        rules.append((item.label, re.compile(item.pattern, flags), item.score))
    if config.enabled_rules is not None:
        builtin_labels = {label for label, _, _ in TOOL_ARGS_RULES}
        if config.enabled_rules & builtin_labels:
            rules = [r for r in rules if r[0] in config.enabled_rules or r[0] not in builtin_labels]
    if config.disabled_rules:
        rules = [r for r in rules if r[0] not in config.disabled_rules]
    return rules


def _iter_string_values(value: Any, path: str) -> Iterable[Tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, Mapping):
        for key, sub in value.items():
            child = f"{path}.{key}" if path else str(key)
            yield from _iter_string_values(sub, child)
    elif isinstance(value, (list, tuple)) and not isinstance(value, (str, bytes)):
        for index, sub in enumerate(value):
            child = f"{path}[{index}]" if path else f"[{index}]"
            yield from _iter_string_values(sub, child)
    # ints/floats/bools/None: nothing to scan.


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


def _path_from_evidence_id(finding: Finding) -> str:
    # Evidence is "<path>: <snippet>"; the path is the prefix before the first ': '.
    if ": " in finding.evidence:
        return finding.evidence.split(": ", 1)[0]
    return ""
