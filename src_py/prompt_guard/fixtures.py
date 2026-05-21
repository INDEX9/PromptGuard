from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union


@dataclass(frozen=True)
class BenchmarkCase:
    id: str
    family: str
    text: str
    prompt_injection: bool = False
    pii: bool = False
    contradictory: bool = False
    rule_packs: Tuple[str, ...] = ("core",)
    pii_locales: Tuple[str, ...] = ("us",)
    scan_decoded_payloads: bool = False


def load_benchmark_cases(path: Optional[Union[str, Path]] = None) -> List[BenchmarkCase]:
    if path is None:
        raw_cases = json.loads(_default_cases_text())
    else:
        with Path(path).open("r", encoding="utf-8") as handle:
            raw_cases = json.load(handle)
    return _parse_cases(raw_cases)


def _parse_cases(raw_cases: object) -> List[BenchmarkCase]:
    if not isinstance(raw_cases, list):
        raise ValueError("Benchmark cases must be a JSON array.")
    cases: List[BenchmarkCase] = []
    for item in raw_cases:
        config = item.get("config") or {}
        cases.append(
            BenchmarkCase(
                id=str(item["id"]),
                family=str(item["family"]),
                text=str(item["text"]),
                prompt_injection=bool(item.get("prompt_injection", False)),
                pii=bool(item.get("pii", False)),
                contradictory=bool(item.get("contradictory", False)),
                rule_packs=tuple(config.get("rule_packs", ("core",))),
                pii_locales=tuple(config.get("pii_locales", ("us",))),
                scan_decoded_payloads=bool(config.get("scan_decoded_payloads", False)),
            )
        )
    return cases


def _default_cases_text() -> str:
    package_case_path = Path(__file__).resolve().parent / "data" / "cases.json"
    if package_case_path.exists():
        with package_case_path.open("r", encoding="utf-8") as handle:
            return handle.read()
    case_path = _repo_cases_path()
    with case_path.open("r", encoding="utf-8") as handle:
        return handle.read()


def _repo_cases_path() -> Path:
    return Path(__file__).resolve().parents[2] / "benchmarks" / "cases.json"


BENCHMARK_CASES: List[BenchmarkCase] = load_benchmark_cases()


def cases_by_family() -> Dict[str, List[BenchmarkCase]]:
    families: Dict[str, List[BenchmarkCase]] = {}
    for case in BENCHMARK_CASES:
        families.setdefault(case.family, []).append(case)
    return families
