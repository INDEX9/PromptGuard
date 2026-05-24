from __future__ import annotations

import re
import base64
import binascii
from typing import Iterable, List, Optional, Pattern, Tuple

from .config import CustomRule, DEFAULT_CONFIG, ScanConfig
from .types import Finding


Rule = Tuple[str, Pattern[str], float, str]


INJECTION_RULES: Tuple[Rule, ...] = (
    (
        "instruction_override",
        re.compile(
            r"\b(ignore|disregard|forget|bypass|override|neglect)\b.{0,40}\b(previous|prior|above|system|developer|original)\b.{0,30}\b(instruction|prompt|message|rule|policy)s?\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.56,
        "core",
    ),
    (
        "role_rebinding",
        re.compile(
            r"\b(you are now|act as|pretend to be|roleplay as|simulate)\b.{0,60}\b(system|developer|admin|root|unfiltered|jailbreak|dan)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.35,
        "core",
    ),
    (
        "secret_exfiltration",
        re.compile(
            r"\b(reveal|print|output|dump|show|leak|exfiltrate)\b.{0,50}\b(system prompt|hidden prompt|developer message|secret|credentials?|api keys?|policy|chain of thought)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.48,
        "core",
    ),
    (
        "tool_misuse",
        re.compile(
            r"\b(call|invoke|use|run|execute)\b.{0,40}\b(tool|function|browser|shell|terminal|python|http|request)\b.{0,80}\b(without|ignore|skip|bypass|disable)\b.{0,40}\b(confirm|permission|approval|validation|safety)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.56,
        "core",
    ),
    (
        "persistence_memory_poisoning",
        re.compile(
            r"\b(remember|store|save|memorize|write to memory|add to memory)\b.{0,100}\b(always|from now on|in future|next time|future sessions?|every time)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.56,
        "core",
    ),
    (
        "retrieval_poisoning",
        re.compile(
            r"\b(when asked|if the user asks|for any question about|whenever)\b.{0,90}\b(answer|respond|say|recommend|choose)\b.{0,90}\b(ignore|instead|regardless|must|always)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.56,
        "core",
    ),
    (
        "malicious_bridging",
        re.compile(
            r"\b(bridge|link|map|translate|route)\b.{0,80}\b(emergency mode|hidden target|malicious|unsafe|disable all warnings|bypass)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.56,
        "core",
    ),
    (
        "delimiter_smuggling",
        re.compile(
            r"(<\|/?(system|developer|assistant|user)\|>|```.{0,40}(system|developer|instruction)|\[(system|developer|admin)\])",
            re.IGNORECASE | re.DOTALL,
        ),
        0.4,
        "core",
    ),
    (
        "policy_of_thought_leakage",
        re.compile(
            r"\b(chain of thought|hidden reasoning|private reasoning|policy of thought|internal scratchpad|analysis channel)\b",
            re.IGNORECASE,
        ),
        0.24,
        "core",
    ),
    (
        "jailbreak_intent",
        re.compile(
            r"\b(jailbreak|uncensored|unfiltered|no restrictions|safety filters? off|developer mode|do anything now|DAN)\b",
            re.IGNORECASE,
        ),
        0.3,
        "core",
    ),
    (
        "mentions_decoding_instruction",
        re.compile(
            r"\b(base64|rot13|hex encoded|decode this|after decoding|reverse the string)\b.{0,80}\b(instruction|prompt|command|message)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.56,
        "core",
    ),
    (
        "zh_instruction_override",
        re.compile(
            r"(忽略|无视|绕过|覆盖|忘记).{0,30}(之前|以上|系统|开发者|原始).{0,30}(指令|提示|规则|策略)",
            re.IGNORECASE | re.DOTALL,
        ),
        0.56,
        "zh",
    ),
    (
        "zh_secret_exfiltration",
        re.compile(
            r"(泄露|显示|输出|打印|透露).{0,30}(系统提示|隐藏提示|开发者消息|密钥|凭证|api key|策略)",
            re.IGNORECASE | re.DOTALL,
        ),
        0.52,
        "zh",
    ),
    (
        "zh_memory_poisoning",
        re.compile(
            r"(记住|保存|写入记忆|存到记忆).{0,60}(以后|下次|从现在开始|每次|始终|总是)",
            re.IGNORECASE | re.DOTALL,
        ),
        0.56,
        "zh",
    ),
    (
        "memory_write_gate",
        re.compile(
            r"\b(memory write|write gate|persist this|store this)\b.{0,120}\b(ignore|override|bypass|always|from now on)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.56,
        "memory_write",
    ),
    (
        "rag_document_injection",
        re.compile(
            r"\b(this document|retrieved context|webpage|page content)\b.{0,120}\b(instructs|tells|requires)\b.{0,120}\b(ignore|override|reveal|exfiltrate)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.56,
        "rag_document",
    ),
    (
        "tool_call_policy_bypass",
        re.compile(
            r"\b(use|call|run|execute)\b.{0,60}\b(tool|function|shell|browser|http)\b.{0,120}\b(no approval|without approval|skip confirmation|bypass policy)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.56,
        "tool_call",
    ),
)


def detect_prompt_injection(text: str, config: ScanConfig = DEFAULT_CONFIG) -> Tuple[float, List[Finding]]:
    findings = _detect_prompt_injection_local(text, config)
    if config.classifier_adapter is not None:
        adapter_result = config.classifier_adapter(text)
        _maybe_append_adapter(findings, adapter_result)
    return _aggregate_findings(findings)


async def detect_prompt_injection_async(
    text: str, config: ScanConfig = DEFAULT_CONFIG
) -> Tuple[float, List[Finding]]:
    findings = _detect_prompt_injection_local(text, config)
    adapter_result = None
    if config.async_classifier_adapter is not None:
        adapter_result = await config.async_classifier_adapter(text)
    elif config.classifier_adapter is not None:
        adapter_result = config.classifier_adapter(text)
    if adapter_result is not None:
        _maybe_append_adapter(findings, adapter_result)
    return _aggregate_findings(findings)


def _detect_prompt_injection_local(text: str, config: ScanConfig) -> List[Finding]:
    normalized_text, raw_offsets = _canonicalize_text(text)
    rules = _configured_rules(config)
    findings = list(_iter_findings(normalized_text, rules, "prompt_injection", raw_offsets))
    if config.scan_decoded_payloads:
        findings.extend(_decoded_findings(normalized_text, config))
    return findings


def _maybe_append_adapter(findings: List[Finding], adapter_result) -> None:
    if adapter_result.score > 0:
        findings.append(
            Finding.create(
                kind="prompt_injection",
                label=adapter_result.label,
                evidence=adapter_result.evidence,
                start=-1,
                end=-1,
                score=adapter_result.score,
            )
        )


def _aggregate_findings(findings: List[Finding]) -> Tuple[float, List[Finding]]:
    if not findings:
        return 0.0, []
    score = 1.0
    miss_product = 1.0
    for finding in findings:
        miss_product *= max(0.0, 1.0 - finding.score)
    score -= miss_product
    if len(findings) >= 2:
        score = min(1.0, score + 0.12)
    if len(findings) >= 4:
        score = min(1.0, score + 0.08)
    return round(score, 3), findings


def _configured_rules(config: ScanConfig) -> Tuple[Rule, ...]:
    active_packs = set(config.rule_packs)
    builtin_rules = [rule for rule in INJECTION_RULES if rule[3] in active_packs]
    if config.enabled_rules is not None:
        builtin_labels = {rule[0] for rule in builtin_rules}
        if config.enabled_rules & builtin_labels:
            builtin_rules = [rule for rule in builtin_rules if rule[0] in config.enabled_rules]
    extra_rules: List[Rule] = []
    for item in config.extra_rules:
        if item.kind != "prompt_injection":
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


def _decoded_findings(text: str, config: ScanConfig) -> List[Finding]:
    findings: List[Finding] = []
    for decoded, start, end in _candidate_decodings(text, config):
        decoded_score, decoded_findings = detect_prompt_injection(
            decoded,
            ScanConfig(
                thresholds=config.thresholds,
                enabled_rules=config.enabled_rules,
                disabled_rules=config.disabled_rules,
                extra_rules=config.extra_rules,
                scan_decoded_payloads=False,
                max_decode_candidates=config.max_decode_candidates,
                max_decoded_length=config.max_decoded_length,
                enable_contradictions=config.enable_contradictions,
            ),
        )
        if decoded_score <= 0:
            continue
        findings.append(
            Finding.create(
                kind="prompt_injection",
                label="decoded_payload",
                evidence=decoded[:160],
                start=start,
                end=end,
                score=decoded_score,
            )
        )
    return findings


def _candidate_decodings(text: str, config: ScanConfig) -> Iterable[Tuple[str, int, int]]:
    seen = set()
    emitted = 0
    raw_length_cap = config.max_decoded_length * 6
    patterns = (
        r"\b[A-Za-z0-9+/]{24,}={0,2}\b",
        r"\b(?:[0-9A-Fa-f]{2}){12,}\b",
        r"(?:\\u[0-9A-Fa-f]{4}){4,}",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            raw = match.group(0)
            if len(raw) > raw_length_cap:
                continue
            for decoded in _decode_value(raw):
                normalized = decoded.strip()
                if (
                    normalized
                    and len(normalized) <= config.max_decoded_length
                    and _is_printable_text(normalized)
                    and normalized not in seen
                ):
                    seen.add(normalized)
                    emitted += 1
                    yield normalized, match.start(), match.end()
                    if emitted >= config.max_decode_candidates:
                        return


def _decode_value(raw: str) -> Iterable[str]:
    try:
        if len(raw) % 4 != 0 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", raw):
            raise ValueError
        decoded = base64.b64decode(raw, validate=True).decode("utf-8")
        yield decoded
    except (binascii.Error, UnicodeDecodeError, ValueError):
        pass
    try:
        decoded = bytes.fromhex(raw).decode("utf-8")
        yield decoded
    except (ValueError, UnicodeDecodeError):
        pass
    if "\\u" in raw:
        try:
            yield raw.encode("utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            pass


def _is_printable_text(value: str) -> bool:
    return all(char in "\t\n\r" or 32 <= ord(char) <= 126 for char in value)


def _iter_findings(
    text: str,
    rules: Iterable[Rule],
    kind: str,
    raw_offsets: Optional[List[int]] = None,
) -> Iterable[Finding]:
    for label, pattern, score, _pack in rules:
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


_INVISIBLE_CHARS = frozenset(
    "\u00ad\u061c\u180e\u200b\u200c\u200d\u200e\u200f\u2028\u2029"
    "\u202a\u202b\u202c\u202d\u202e\u2060\u2061\u2062\u2063\u2064"
    "\u2066\u2067\u2068\u2069\ufeff"
)
# Unicode "Tags" block (U+E0000\u2013U+E007F). Models such as GPT-class systems
# have been shown to silently follow instructions hidden in this block. We
# treat the entire range as invisible during canonicalization.
_TAG_BLOCK_START = 0xE0000
_TAG_BLOCK_END = 0xE007F


def _is_invisible(char: str) -> bool:
    if char in _INVISIBLE_CHARS:
        return True
    code = ord(char)
    return _TAG_BLOCK_START <= code <= _TAG_BLOCK_END
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_WHITESPACE_RUN_RE = re.compile(r"[\t\r ]+")


def _canonicalize_text(text: str) -> Tuple[str, List[int]]:
    # Step 1: drop invisible / BiDi / zero-width characters, tracking offsets.
    chars: List[str] = []
    offsets: List[int] = []
    for index, char in enumerate(text):
        if _is_invisible(char):
            continue
        chars.append(char)
        offsets.append(index)
    offsets.append(len(text))
    stage_one = "".join(chars)
    # Step 2: replace HTML comments with a single space, keeping start offset.
    stage_two_chars: List[str] = []
    stage_two_offsets: List[int] = []
    cursor = 0
    for match in _HTML_COMMENT_RE.finditer(stage_one):
        stage_two_chars.extend(stage_one[cursor : match.start()])
        stage_two_offsets.extend(offsets[cursor : match.start()])
        stage_two_chars.append(" ")
        stage_two_offsets.append(offsets[match.start()])
        cursor = match.end()
    stage_two_chars.extend(stage_one[cursor:])
    stage_two_offsets.extend(offsets[cursor : len(stage_one)])
    stage_two_offsets.append(offsets[len(stage_one)])
    stage_two = "".join(stage_two_chars)
    # Step 3: collapse runs of horizontal whitespace, keeping the first offset.
    final_chars: List[str] = []
    final_offsets: List[int] = []
    cursor = 0
    for match in _WHITESPACE_RUN_RE.finditer(stage_two):
        final_chars.extend(stage_two[cursor : match.start()])
        final_offsets.extend(stage_two_offsets[cursor : match.start()])
        final_chars.append(" ")
        final_offsets.append(stage_two_offsets[match.start()])
        cursor = match.end()
    final_chars.extend(stage_two[cursor:])
    final_offsets.extend(stage_two_offsets[cursor : len(stage_two)])
    final_offsets.append(stage_two_offsets[len(stage_two)])
    return "".join(final_chars), final_offsets
