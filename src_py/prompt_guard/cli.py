from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from .config import DEFAULT_CONFIG, ScanConfig
from .core import scan_text
from .types import DetectionReport


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="prompt-guard",
        description="Scan text for prompt injection, PII, and contradictions.",
    )
    parser.add_argument("paths", nargs="*", help="Files to scan. Reads stdin when omitted.")
    parser.add_argument("--config", type=Path, help="Path to a JSON ScanConfig file.")
    parser.add_argument("--json", action="store_true", help="Emit JSON reports instead of human-readable output.")
    parser.add_argument("--no-evidence", action="store_true", help="Strip evidence snippets from output.")
    parser.add_argument(
        "--fail-on",
        choices=["injection", "pii", "contradiction", "any", "none"],
        default="any",
        help="Which detections cause a non-zero exit code (default: any).",
    )
    args = parser.parse_args(argv)

    config = ScanConfig.from_file(args.config) if args.config else DEFAULT_CONFIG
    include_evidence = not args.no_evidence

    reports: List[Tuple[str, DetectionReport]] = []
    flagged = False
    for name, text in _read_inputs(args.paths):
        report = scan_text(text, include_evidence=include_evidence, config=config)
        reports.append((name, report))
        if _should_fail(report, args.fail_on):
            flagged = True

    if args.json:
        payload = [dict(source=name, **report.as_dict()) for name, report in reports]
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for name, report in reports:
            _print_human(name, report)

    return 1 if flagged else 0


def _read_inputs(paths: List[str]) -> List[Tuple[str, str]]:
    if not paths:
        return [("<stdin>", sys.stdin.read())]
    return [(path, Path(path).read_text(encoding="utf-8")) for path in paths]


def _should_fail(report: DetectionReport, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    if fail_on == "injection":
        return report.is_prompt_injection
    if fail_on == "pii":
        return report.has_pii
    if fail_on == "contradiction":
        return report.is_contradictory
    return report.is_prompt_injection or report.has_pii or report.is_contradictory


def _print_human(name: str, report: DetectionReport) -> None:
    flags = []
    if report.is_prompt_injection:
        flags.append(f"prompt_injection={report.prompt_injection_score}")
    if report.has_pii:
        flags.append(f"pii={report.pii_score}")
    if report.is_contradictory:
        flags.append(f"contradiction={report.contradiction_score}")
    print(f"{name}: {'; '.join(flags) if flags else 'clean'}")
    for finding in list(report.prompt_injection_findings) + list(report.pii_findings):
        print(f"  - [{finding.severity}] {finding.label} ({finding.category}) score={finding.score}")


if __name__ == "__main__":
    sys.exit(main())
