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
Thresholds(
    prompt_injection=0.55,
    pii=0.5,
    contradiction=0.6,
    reviewer_block=0.75,
    tool_args=0.55,
    output_risk=0.55,
)
```

### `scan_tool_args` / `detect_tool_args`

```python
scan_tool_args(args, config=DEFAULT_CONFIG) -> ToolArgsReport
detect_tool_args(args, config=DEFAULT_CONFIG) -> (float, list[Finding])
```

Walks structured tool/function call arguments (`str | dict | list`)
recursively and scans every string value. Rule set covers SQL/NoSQL
injection, shell metacharacters, path traversal, SSRF (private and cloud
metadata URLs), code-interpreter primitives, Windows command injection.
Each finding's `evidence` is prefixed with the dotted arg path
(e.g. `"steps[0].cmd: ls; rm -rf /"`).

### `scan_output` / `detect_output_risk`

```python
scan_output(text, include_evidence=True, config=DEFAULT_CONFIG) -> OutputReport
detect_output_risk(text, config=DEFAULT_CONFIG) -> (float, list[Finding])
```

Output-side detection for LLM responses: system-prompt echo, chat-template
token leakage (`<|im_start|>`, `[INST]`, ...), internal instruction
disclosure, refusal-then-compliance jailbreak markers. `OutputReport`
also carries reused PII findings via `detect_pii`.

### Secrets PII locale

Opt in via `pii_locales=["secrets"]` (combinable with other locales) to
enable high-confidence vendor credential fingerprints: AWS access key id,
GitHub PAT, OpenAI / Anthropic / Slack / Stripe / Google API keys, JWTs,
PEM private keys, and GCP service-account JSON.

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
  thresholds: { promptInjection: number; pii: number; contradiction: number; reviewerBlock: number; toolArgs: number; outputRisk: number };
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
  kind?: "prompt_injection" | "pii" | "tool_args" | "output_risk";
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

### `scanToolArgs` / `detectToolArgs`

```ts
scanToolArgs(args: unknown, config?: ScanConfigInput): ToolArgsReport
detectToolArgs(args: unknown, config?: ScanConfigInput): [number, Finding[]]
```

Same semantics as the Python equivalents. Accepts strings, arrays, plain
objects, or nested combinations. Findings' `evidence` field is prefixed
with the dotted arg path.

### `scanOutput` / `detectOutputRisk`

```ts
scanOutput(text: string, options?: { includeEvidence?: boolean; config?: ScanConfigInput }): OutputReport
detectOutputRisk(text: string, config?: ScanConfigInput): [number, Finding[]]
```

Output-side risk detection for LLM responses with reused PII findings.

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
