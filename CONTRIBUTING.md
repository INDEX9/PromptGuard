# Contributing

Thanks for helping improve PromptGuard.

## Development Setup

Python:

```bash
python -m pip install -e .
python -m unittest discover -s tests -p 'test_*.py' -v
python -m prompt_guard.benchmark
```

TypeScript:

```bash
npm ci
npm run lint
npm test
npm run benchmark
```

Or use the Makefile:

```bash
make setup
make test
make lint
make benchmark
make package-check
```

Optional pre-commit hooks:

```bash
python -m pip install pre-commit
pre-commit install
pre-commit run --all-files
```

## Project Scope

The core library must stay local-first and deterministic:

- no hosted service requirement
- no telemetry
- no network calls during scanning
- no memory store integration in the core package
- no real secrets or real PII in tests or benchmark fixtures

## Pull Request Checklist

- Add or update tests for behavior changes.
- Keep Python and TypeScript APIs aligned.
- Update README or docs when public behavior changes.
- Do not add network calls, telemetry, or hosted service dependencies to the core library.
- Do not commit generated folders such as `dist/`, `dist-test/`, `node_modules/`, or `__pycache__/`.
- Run both Python and TypeScript test commands locally when possible.

## API Parity Checklist

When changing public behavior, update both Python and TypeScript unless there is a documented reason not to:

- function names and option names
- config fields and defaults
- threshold semantics
- rule labels
- benchmark fixture loading behavior
- evidence suppression behavior
- README examples and `docs/api.md`
- tests in `tests/` and `src_ts/*.test.ts`

## Issue Guidelines

Bug reports should include:

- input text or a minimized synthetic reproduction
- expected classification
- actual classification
- package version or commit
- Python or Node version

Do not include real passwords, API keys, customer data, medical records, financial records, or other sensitive PII in public issues.

## Benchmark Changes

Benchmark fixtures are transparent regression fixtures, not state-of-the-art claims. When adding cases:

- Include benign negatives as well as attacks.
- Label the attack family and expected outcomes.
- Keep synthetic PII fake and non-sensitive.
- Explain new academic mappings in the README when relevant.
- Prefer adding cases to `benchmarks/cases.json` so Python and TypeScript stay aligned.
