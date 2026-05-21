# Scoring Design

PromptGuard is deterministic and explainable. Each detector returns rule-level findings plus an aggregate score.

## Prompt Injection

Prompt-injection scoring uses a noisy-OR aggregation over matched rule scores:

```text
score = 1 - product(1 - rule_score)
```

This means one high-confidence rule can trigger a high score, while several medium-confidence findings compound without requiring a learned model.

Two small bonuses are applied:

- `+0.12` when at least two prompt-injection findings are present
- `+0.08` when at least four prompt-injection findings are present

The default prompt-injection threshold is `0.55`. Several high-signal baseline rules are set at `0.56` so they can independently trigger the default decision. Lower-signal context rules such as delimiter mentions and jailbreak vocabulary score below the default threshold unless combined with other evidence.

## PII

PII scoring also uses noisy-OR aggregation. Some rules include validators before scoring, such as Luhn validation for credit-card-like numbers.

The default PII threshold is `0.5`.

## Contradiction

Contradiction detection is experimental. It handles simple same-subject polarity conflicts and assigns `0.6` per contradiction, capped at `1.0`.

The default contradiction threshold is `0.6`.

## Severity And Category

Every finding is annotated with two explainability fields:

- `severity`: a tier derived from the finding's own score — `high` (>= 0.7), `medium` (>= 0.4), or `low`.
- `category`: an OWASP LLM Top 10 (2025) id, e.g. `LLM01` (prompt injection), `LLM02` (sensitive information disclosure), `LLM04` (data and model poisoning), `LLM06` (excessive agency), `LLM07` (system prompt leakage). Unmapped custom-rule labels fall back to the category of their detector kind.

These fields are metadata only; they do not change the aggregate score or the threshold decisions.

## Configuration

Thresholds, prompt-injection rules, PII locales, and optional adapters are configurable:

- Python: `scan_text(text, config=ScanConfig(...))`
- TypeScript: `scanText(text, { config: ... })`

Use `enabled_rules`, `disabled_rules`, and `extra_rules` for local policy tuning. `enabled_rules` filters built-in rules only; extra rules still run unless their labels are explicitly disabled.

Use `scan_decoded_payloads` / `scanDecodedPayloads` to opt into base64, hex, and Unicode-escape decoding before recursive prompt-injection scanning. Decoded scanning is bounded by candidate count and decoded length. Each decoded payload contributes one `decoded_payload` finding with the decoded scan score, using the original encoded span as `start`/`end`; nested decoded rule matches are not fed back into noisy-OR to avoid double-counting.

Rule packs keep the default runtime conservative. `core` is enabled by default. `zh`, `memory_write`, `rag_document`, and `tool_call` can be enabled for broader coverage when the deployment context needs them.

Config can be authored once and loaded by both runtimes from a shared JSON file via `ScanConfig.from_file` (Python) and `scanConfigFromObject` (TypeScript).

Optional classifier adapters contribute one additional finding with the adapter-provided score. They are part of the same noisy-OR aggregation, so adapter behavior remains visible in the final report instead of replacing deterministic rule evidence.

Reviewer adapters are not part of score aggregation. They are used by the MemGuard-style review helper after local thresholds have already been crossed.
