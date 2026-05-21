# API Reference

## Python

### `scan_text` / `scan_text_async` / `scan_many`

```python
scan_text(text: str, include_evidence: bool = True, config: ScanConfig = DEFAULT_CONFIG) -> DetectionReport
scan_text_async(text: str, include_evidence: bool = True, config: ScanConfig = DEFAULT_CONFIG) -> DetectionReport
scan_many(texts: Iterable[str], include_evidence: bool = True, config: ScanConfig = DEFAULT_CONFIG) -> list[DetectionReport]
```

Scan a snippet (or batch) for prompt injection, PII, and simple contradictions.
`scan_text_async` awaits `async_classifier_adapter` when one is configured.
Set `include_evidence=False` before writing reports to logs or durable storage.

### `ScanConfig`

```python
ScanConfig.with_rules(
    enabled_rules=None,
    disabled_rules=(),
    extra_rules=(),
    rule_packs=("core",),
    pii_locales=("us",),
    thresholds=Thresholds(),
    scan_decoded_payloads=False,
    max_decode_candidates=16,
    max_decoded_length=4096,
    enable_contradictions=True,
    classifier_adapter=None,
    reviewer_adapter=None,
    async_classifier_adapter=None,
    async_reviewer_adapter=None,
)

ScanConfig.from_dict(data: dict) -> ScanConfig
ScanConfig.from_file(path: str | Path) -> ScanConfig
```

`from_dict` / `from_file` load the canonical snake_case config format. Adapter
callbacks cannot be expressed in JSON and are always left unset.

`enabled_rules` filters built-in rules only, and only within the detector
whose labels it references; `extra_rules` always run unless their label is in
`disabled_rules`.

Built-in prompt-injection rule packs: `core`, `zh`, `memory_write`,
`rag_document`, `tool_call`.

PII locale packs: `us`, `cn`, `eu`. Global PII rules (email, credit-card-like
numbers, IPv4, API-key-like tokens) always run.

### `Thresholds`

```python
Thresholds(prompt_injection=0.55, pii=0.5, contradiction=0.6, reviewer_block=0.75)
```

### `redact_pii` / `redact_text`

```python
redact_pii(text, replacement="[REDACTED]", config=DEFAULT_CONFIG, strategy="full") -> str
redact_text(text, replacement="[REDACTED]", config=DEFAULT_CONFIG, strategy="full") -> str
```

`redact_pii` replaces PII spans; `redact_text` also replaces prompt-injection
spans. `strategy` is `full`, `partial`, or `type_label`. Findings without a
resolvable offset (classifier-adapter findings) are skipped.

### `review_text_write` / `review_text_write_async`

```python
review_text_write(text, config=DEFAULT_CONFIG) -> ReviewDecision
review_text_write_async(text, config=DEFAULT_CONFIG) -> ReviewDecision
```

Runs a local scan and returns `approve`, `review`, or `block`. The reviewer
adapter receives an evidence-bearing report; the report returned to the caller
has evidence stripped. The block threshold is `thresholds.reviewer_block`.

### `DetectionReport.as_dict`

Returns the canonical snake_case wire format. Each finding includes `kind`,
`label`, `evidence`, `start`, `end`, `score`, `severity`, and `category`.

## TypeScript

### `scanText` / `scanTextAsync` / `scanMany`

```ts
scanText(text: string, options?: { includeEvidence?: boolean; config?: ScanConfigInput }): DetectionReport
scanTextAsync(text: string, options?): Promise<DetectionReport>
scanMany(texts: Iterable<string>, options?): DetectionReport[]
```

### `ScanConfig`

```ts
interface ScanConfig {
  thresholds: { promptInjection: number; pii: number; contradiction: number; reviewerBlock: number };
  enabledRules?: string[] | Set<string>;
  disabledRules: string[] | Set<string>;
  extraRules: CustomRule[];
  rulePacks: string[] | Set<string>;
  piiLocales: string[] | Set<string>;
  scanDecodedPayloads: boolean;
  maxDecodeCandidates: number;
  maxDecodedLength: number;
  enableContradictions: boolean;
  classifierAdapter?: ClassifierAdapter;
  reviewerAdapter?: ReviewerAdapter;
  asyncClassifierAdapter?: AsyncClassifierAdapter;
  asyncReviewerAdapter?: AsyncReviewerAdapter;
}
```

`ScanConfigInput` is the public input type: every field is optional and
`thresholds` accepts a partial object. `scanConfigFromObject(json)` converts a
parsed snake_case config object into a `ScanConfigInput`.

Custom rules use semantic flags in both runtimes:

```ts
interface CustomRule {
  label: string;
  pattern: string;
  score: number;
  kind?: "prompt_injection" | "pii";
  caseSensitive?: boolean;
  dotall?: boolean;
}
```

### `redactPii` / `redactText`

```ts
redactPii(text, replacement?, config?, strategy?): string
redactText(text, replacement?, config?, strategy?): string
```

### `reviewTextWrite` / `reviewTextWriteAsync`

```ts
reviewTextWrite(text: string, config?: ScanConfigInput): ReviewDecision
reviewTextWriteAsync(text: string, config?: ScanConfigInput): Promise<ReviewDecision>
```

### `reportToDict`

```ts
reportToDict(report: DetectionReport): Record<string, unknown>
```

Serializes a report into the canonical snake_case wire format, byte-for-byte
compatible with the Python `DetectionReport.as_dict()`.

### `runBenchmark`

```ts
runBenchmark(cases?: BenchmarkCase[]): Record<string, unknown>
```

Returns family-level detection rates, task-level accuracy / precision / recall /
F1 / confusion matrices, and mean / p95 / max scan latency.

## CLI

```
prompt-guard [--config FILE] [--json] [--no-evidence] [--fail-on MODE] [files...]
```

Scans the given files (or stdin) and exits `1` when a detection crosses its
threshold. `--fail-on` is one of `injection`, `pii`, `contradiction`, `any`
(default), or `none`. Shipped as a Python console script and an npm `bin`.

## Report Shape

Reports include:

- boolean decisions and numeric scores
- rule findings with `severity` and OWASP LLM Top 10 `category`
- optional evidence spans with raw-text offsets
- simple contradiction records
- the `thresholds` used to compute the decisions
