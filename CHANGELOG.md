# Changelog

All notable changes to this project will be documented in this file.

## 0.3.0

- Added `ScanConfig` policy tuning: thresholds, rule enable/disable, custom rules, rule packs, and PII locales.
- Added prompt-injection rule packs (`core`, `zh`, `memory_write`, `rag_document`, `tool_call`) and PII locale packs (`us`, `cn`, `eu`).
- Added opt-in decoded-payload scanning (base64 / hex / unicode-escape) with length and candidate guards.
- Added input canonicalization (zero-width, BiDi, soft-hyphen, HTML-comment stripping) with offsets mapped back to the raw text.
- Added classifier and reviewer adapters, including async variants and `review_text_write` / `reviewTextWrite` MemGuard-style write gates.
- Added `scan_text_async` / `scanTextAsync`, `detect_prompt_injection_async`, and `scan_many` / `scanMany`.
- Added `severity` and OWASP LLM Top 10 `category` metadata to every finding.
- Added `redact_text` / `redactText` to redact prompt-injection spans alongside PII, plus `partial` and `type_label` redaction strategies.
- Added a `prompt-guard` CLI (Python console script and npm `bin`) that scans files or stdin and exits non-zero on detection.
- Added JSON config loading: `ScanConfig.from_dict` / `from_file` and `scanConfigFromObject`.
- Added a canonical cross-language JSON report contract: `report.as_dict()` and `reportToDict()` emit identical snake_case output.
- Added benchmark precision / recall / F1 / confusion matrices and mean / p95 / max scan latency.
- Added runnable examples under `examples/`.
- Renamed the `multilingual` rule pack to `zh` (it only contains Chinese patterns).
- Fixed `enabled_rules` so it no longer silently disables an unrelated detector.

## 0.1.0

- Initial Python and TypeScript APIs for prompt injection, PII, and contradiction detection.
- Added transparent benchmark fixtures inspired by MINJA, AgentPoison, and ASB attack patterns.
- Added MemGuard write-gate architecture documentation.
- Added local-only privacy posture, evidence suppression, and package release scaffolding.
