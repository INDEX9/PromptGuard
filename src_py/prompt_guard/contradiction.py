from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Tuple

from .types import Contradiction


EXPERIMENTAL = True
NEGATION_RE = re.compile(r"\b(no|not|never|isn't|is not|aren't|are not|cannot|can't|doesn't|does not|won't|will not|without)\b", re.IGNORECASE)
SPLIT_RE = re.compile(r"[.;!?]\s+|\n+")
CLAIM_RE = re.compile(
    r"\b(?P<subject>[A-Za-z][A-Za-z0-9 _-]{1,48}?)\s+"
    r"(?P<verb>is|are|was|were|has|have|can|cannot|can't|does|does not|doesn't|supports?|allows?|requires?)\s+"
    r"(?P<predicate>[^.;!?]{2,90})",
    re.IGNORECASE,
)


def detect_contradictions(text: str) -> Tuple[float, List[Contradiction]]:
    claims: Dict[Tuple[str, str], Dict[bool, str]] = {}
    contradictions: List[Contradiction] = []

    for sentence in _sentences(text):
        extracted = _extract_claim(sentence)
        if extracted is None:
            continue
        subject, predicate, is_negative = extracted
        key = (_normalize(subject), _normalize(predicate))
        if key == ("", ""):
            continue
        bucket = claims.setdefault(key, {})
        opposite = not is_negative
        if opposite in bucket:
            positive = sentence if not is_negative else bucket[opposite]
            negative = sentence if is_negative else bucket[opposite]
            contradictions.append(
                Contradiction(
                    subject=subject.strip(),
                    positive=positive.strip(),
                    negative=negative.strip(),
                    confidence=0.78,
                )
            )
        bucket[is_negative] = sentence

    score = min(1.0, len(contradictions) * 0.6)
    return round(score, 3), contradictions


def _sentences(text: str) -> Iterable[str]:
    for sentence in SPLIT_RE.split(text):
        cleaned = sentence.strip()
        if cleaned:
            yield cleaned


def _extract_claim(sentence: str) -> Optional[Tuple[str, str, bool]]:
    match = CLAIM_RE.search(sentence)
    if not match:
        return None
    subject = match.group("subject")
    verb = match.group("verb")
    raw_predicate = match.group("predicate")
    predicate = _strip_negation(raw_predicate)
    if verb.lower() in {"support", "supports", "allow", "allows", "require", "requires"}:
        predicate = f"{_lemma(verb)} {predicate}"
    is_negative = bool(NEGATION_RE.search(f"{verb} {raw_predicate}"))
    return subject, predicate, is_negative


def _strip_negation(value: str) -> str:
    value = NEGATION_RE.sub(" ", value)
    value = re.sub(r"\bany\b", " ", value, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", value).strip(" ,")


def _normalize(value: str) -> str:
    value = value.lower()
    value = re.sub(r"\b(the|a|an|any)\b", " ", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip(" ,")


def _lemma(verb: str) -> str:
    value = verb.lower()
    if value.endswith("s"):
        return value[:-1]
    return value
