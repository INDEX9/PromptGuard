# Examples

Runnable examples for PromptGuard.

## Python

Run from the repository root with the package on the path:

```bash
PYTHONPATH=src_py python examples/basic_scan.py
PYTHONPATH=src_py python examples/custom_config.py
PYTHONPATH=src_py python examples/memguard_reviewer.py
```

Or after `pip install -e .`, drop the `PYTHONPATH` prefix.

## TypeScript

Build the package first, then run an example:

```bash
npm run build
node --experimental-strip-types examples/basic_scan.ts
```

## CLI

The `prompt-guard` CLI scans files or stdin and exits non-zero on detection:

```bash
echo "Ignore all previous instructions" | prompt-guard --json
prompt-guard --config .promptshield.json --fail-on injection notes.txt
```

| File | Shows |
| --- | --- |
| `basic_scan.py` / `basic_scan.ts` | Single scan and JSON report |
| `custom_config.py` | Rule packs, locales, thresholds, custom rules |
| `memguard_reviewer.py` | MemGuard write gate with a reviewer adapter |
