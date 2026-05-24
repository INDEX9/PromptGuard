from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, Optional, Set, Tuple, Union


@dataclass(frozen=True)
class Thresholds:
    prompt_injection: float = 0.55
    pii: float = 0.5
    contradiction: float = 0.6
    reviewer_block: float = 0.75
    tool_args: float = 0.55
    output_risk: float = 0.55


@dataclass(frozen=True)
class AdapterResult:
    label: str
    score: float
    evidence: str = ""


ClassifierAdapter = Callable[[str], AdapterResult]
AsyncClassifierAdapter = Callable[[str], Awaitable[AdapterResult]]
ReviewerAdapter = Callable[[str, object], AdapterResult]
AsyncReviewerAdapter = Callable[[str, object], Awaitable[AdapterResult]]


@dataclass(frozen=True)
class CustomRule:
    label: str
    pattern: str
    score: float
    kind: str = "prompt_injection"
    case_sensitive: bool = False
    dotall: bool = True


@dataclass(frozen=True)
class ScanConfig:
    thresholds: Thresholds = field(default_factory=Thresholds)
    enabled_rules: Optional[Set[str]] = None
    disabled_rules: Set[str] = field(default_factory=set)
    extra_rules: Tuple[CustomRule, ...] = ()
    rule_packs: Set[str] = field(default_factory=lambda: {"core"})
    pii_locales: Set[str] = field(default_factory=lambda: {"us"})
    scan_decoded_payloads: bool = False
    max_decode_candidates: int = 16
    max_decoded_length: int = 4096
    enable_contradictions: bool = True
    classifier_adapter: Optional[ClassifierAdapter] = None
    reviewer_adapter: Optional[ReviewerAdapter] = None
    async_classifier_adapter: Optional[AsyncClassifierAdapter] = None
    async_reviewer_adapter: Optional[AsyncReviewerAdapter] = None

    @classmethod
    def with_rules(
        cls,
        enabled_rules: Optional[Iterable[str]] = None,
        disabled_rules: Iterable[str] = (),
        extra_rules: Iterable[CustomRule] = (),
        rule_packs: Iterable[str] = ("core",),
        pii_locales: Iterable[str] = ("us",),
        thresholds: Optional[Thresholds] = None,
        scan_decoded_payloads: bool = False,
        max_decode_candidates: int = 16,
        max_decoded_length: int = 4096,
        enable_contradictions: bool = True,
        classifier_adapter: Optional[ClassifierAdapter] = None,
        reviewer_adapter: Optional[ReviewerAdapter] = None,
        async_classifier_adapter: Optional[AsyncClassifierAdapter] = None,
        async_reviewer_adapter: Optional[AsyncReviewerAdapter] = None,
    ) -> "ScanConfig":
        return cls(
            thresholds=thresholds if thresholds is not None else Thresholds(),
            enabled_rules=set(enabled_rules) if enabled_rules is not None else None,
            disabled_rules=set(disabled_rules),
            extra_rules=tuple(extra_rules),
            rule_packs=set(rule_packs),
            pii_locales=set(pii_locales),
            scan_decoded_payloads=scan_decoded_payloads,
            max_decode_candidates=max_decode_candidates,
            max_decoded_length=max_decoded_length,
            enable_contradictions=enable_contradictions,
            classifier_adapter=classifier_adapter,
            reviewer_adapter=reviewer_adapter,
            async_classifier_adapter=async_classifier_adapter,
            async_reviewer_adapter=async_reviewer_adapter,
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanConfig":
        """Build a config from a parsed JSON object (snake_case keys).

        Adapter callbacks cannot be expressed in JSON and are always left unset.
        """
        thresholds_data = data.get("thresholds") or {}
        thresholds = Thresholds(
            prompt_injection=float(thresholds_data.get("prompt_injection", 0.55)),
            pii=float(thresholds_data.get("pii", 0.5)),
            contradiction=float(thresholds_data.get("contradiction", 0.6)),
            reviewer_block=float(thresholds_data.get("reviewer_block", 0.75)),
            tool_args=float(thresholds_data.get("tool_args", 0.55)),
            output_risk=float(thresholds_data.get("output_risk", 0.55)),
        )
        extra_rules = tuple(
            CustomRule(
                label=str(rule["label"]),
                pattern=str(rule["pattern"]),
                score=float(rule["score"]),
                kind=str(rule.get("kind", "prompt_injection")),
                case_sensitive=bool(rule.get("case_sensitive", False)),
                dotall=bool(rule.get("dotall", True)),
            )
            for rule in data.get("extra_rules", [])
        )
        return cls.with_rules(
            enabled_rules=data.get("enabled_rules"),
            disabled_rules=data.get("disabled_rules", ()),
            extra_rules=extra_rules,
            rule_packs=data.get("rule_packs", ("core",)),
            pii_locales=data.get("pii_locales", ("us",)),
            thresholds=thresholds,
            scan_decoded_payloads=bool(data.get("scan_decoded_payloads", False)),
            max_decode_candidates=int(data.get("max_decode_candidates", 16)),
            max_decoded_length=int(data.get("max_decoded_length", 4096)),
            enable_contradictions=bool(data.get("enable_contradictions", True)),
        )

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "ScanConfig":
        """Load a config from a JSON file (e.g. .promptshield.json)."""
        with Path(path).open("r", encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))


DEFAULT_CONFIG = ScanConfig()
