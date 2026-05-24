# Changelog

All notable changes to this project will be documented in this file.

## 0.4.0

- Added output-side risk detection: `scan_output` / `scanOutput` returning an `OutputReport` with rules for system-prompt echo, chat-template token leakage, internal instruction disclosure, refusal-then-compliance jailbreak markers, and sensitive-topic response templates. Reuses the PII detector for leaked PII in model responses.
- Added tool-args injection detection: `scan_tool_args` / `scanToolArgs` accepts `str | dict | list` (recursing through structured arguments) with rules for SQL/NoSQL injection, shell metacharacters, path traversal, SSRF against private and cloud-metadata endpoints, code-interpreter primitives, and Windows command injection. Findings include the dotted path of the offending arg.
- Added a `secrets` PII locale with high-confidence vendor credential fingerprints: AWS access key id, GitHub personal access tokens, OpenAI / Anthropic / Slack / Stripe / Google API keys, JWTs, PEM private keys, and GCP service-account JSON.
- Hardened canonicalization against the Unicode Tags block (U+E0000–U+E007F) used in tag-character smuggling; offsets still map back to the raw text and surrogate pairs are evaluated as whole code points in TypeScript.
- Added `Thresholds.tool_args` and `Thresholds.output_risk` (both default `0.55`); both are loadable from JSON config files.
- Expanded the OWASP LLM Top 10 mapping table to cover the new tool-args / output-risk labels and the secrets pack (LLM02 / LLM06 / LLM07).

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
