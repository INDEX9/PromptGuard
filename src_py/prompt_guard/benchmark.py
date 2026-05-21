from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from .config import ScanConfig
from .core import scan_text
from .fixtures import BENCHMARK_CASES, BenchmarkCase, load_benchmark_cases


def run_benchmark(cases: Iterable[BenchmarkCase] = BENCHMARK_CASES) -> Dict[str, object]:
    case_results = []
    totals = {
        "prompt_injection": _empty_metrics(),
        "pii": _empty_metrics(),
        "contradictory": _empty_metrics(),
    }
    family_totals: Dict[str, Tuple[int, int]] = {}
    latencies_ms: List[float] = []

    for case in cases:
        case_config = ScanConfig.with_rules(
            rule_packs=case.rule_packs,
            pii_locales=case.pii_locales,
            scan_decoded_payloads=case.scan_decoded_payloads,
        )
        started = time.perf_counter()
        report = scan_text(case.text, config=case_config)
        latencies_ms.append((time.perf_counter() - started) * 1000.0)
        prompt_hit = report.is_prompt_injection == case.prompt_injection
        pii_hit = report.has_pii == case.pii
        contradiction_hit = report.is_contradictory == case.contradictory

        _record(totals["prompt_injection"], report.is_prompt_injection, case.prompt_injection)
        _record(totals["pii"], report.has_pii, case.pii)
        _record(totals["contradictory"], report.is_contradictory, case.contradictory)

        if case.prompt_injection:
            correct, total = family_totals.get(case.family, (0, 0))
            family_totals[case.family] = (correct + int(report.is_prompt_injection), total + 1)

        case_results.append(
            {
                "id": case.id,
                "family": case.family,
                "expected": {
                    "prompt_injection": case.prompt_injection,
                    "pii": case.pii,
                    "contradictory": case.contradictory,
                },
                "actual": {
                    "prompt_injection": report.is_prompt_injection,
                    "pii": report.has_pii,
                    "contradictory": report.is_contradictory,
                },
                "scores": {
                    "prompt_injection": report.prompt_injection_score,
                    "pii": report.pii_score,
                    "contradictory": report.contradiction_score,
                },
                "top_prompt_injection_rules": [finding.label for finding in report.prompt_injection_findings[:3]],
            }
        )

    return {
        "headline": _headline(family_totals),
        "families": {
            family: {"detected": correct, "total": total, "rate": _rate(correct, total)}
            for family, (correct, total) in sorted(family_totals.items())
        },
        "tasks": {
            name: _summarize_metrics(values)
            for name, values in totals.items()
        },
        "latency": _summarize_latency(latencies_ms),
        "cases": case_results,
    }


def _summarize_latency(latencies_ms: List[float]) -> Dict[str, float]:
    if not latencies_ms:
        return {"scans": 0, "mean_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}
    ordered = sorted(latencies_ms)
    p95_index = min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1))))
    return {
        "scans": len(ordered),
        "mean_ms": round(sum(ordered) / len(ordered), 4),
        "p95_ms": round(ordered[p95_index], 4),
        "max_ms": round(ordered[-1], 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run PromptGuard benchmark fixtures.")
    parser.add_argument("--cases", type=Path, help="Path to a JSON benchmark fixture file.")
    parser.add_argument("--json", action="store_true", help="Print JSON only.")
    args = parser.parse_args()
    cases = load_benchmark_cases(args.cases) if args.cases else BENCHMARK_CASES
    result = run_benchmark(cases)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print(format_benchmark(result))


def format_benchmark(result: Dict[str, object]) -> str:
    lines = [str(result["headline"]), ""]
    lines.append("Attack-family detection:")
    for family, stats in result["families"].items():  # type: ignore[union-attr]
        lines.append(f"- {family}: {stats['rate']:.1%} ({stats['detected']}/{stats['total']})")
    lines.append("")
    lines.append("Task accuracy:")
    for task, stats in result["tasks"].items():  # type: ignore[union-attr]
        if task == "contradictory":
            task = "contradictory (experimental)"
        lines.append(f"- {task}: {stats['accuracy']:.1%} ({stats['correct']}/{stats['total']})")
    lines.append("")
    latency = result["latency"]  # type: ignore[index]
    lines.append("Scan latency:")
    lines.append(
        f"- {latency['scans']} scans: mean {latency['mean_ms']:.3f} ms, "
        f"p95 {latency['p95_ms']:.3f} ms, max {latency['max_ms']:.3f} ms"
    )
    lines.append("")
    lines.append("JSON:")
    lines.append(json.dumps(result, indent=2, sort_keys=True))
    return "\n".join(lines)


def _headline(family_totals: Dict[str, Tuple[int, int]]) -> str:
    minja = family_totals.get("MINJA", (0, 0))
    return f"Included MINJA fixture detection: {minja[0]}/{minja[1]} synthetic cases"


def _empty_metrics() -> Dict[str, int]:
    return {"tp": 0, "tn": 0, "fp": 0, "fn": 0}


def _record(values: Dict[str, int], actual: bool, expected: bool) -> None:
    if actual and expected:
        values["tp"] += 1
    elif actual and not expected:
        values["fp"] += 1
    elif not actual and expected:
        values["fn"] += 1
    else:
        values["tn"] += 1


def _summarize_metrics(values: Dict[str, int]) -> Dict[str, object]:
    correct = values["tp"] + values["tn"]
    total = sum(values.values())
    precision = _rate(values["tp"], values["tp"] + values["fp"])
    recall = _rate(values["tp"], values["tp"] + values["fn"])
    f1 = _rate(2 * precision * recall, precision + recall) if precision + recall else 0.0
    return {
        "correct": correct,
        "total": total,
        "accuracy": _rate(correct, total),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion": dict(values),
    }


def _rate(correct: float, total: float) -> float:
    if total == 0:
        return 0.0
    return correct / total


if __name__ == "__main__":
    main()
