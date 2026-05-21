# Release Checklist

1. Update versions in `pyproject.toml` and `package.json`.
2. Update `CHANGELOG.md`.
3. Replace placeholder repository URLs if this is the first public release.
4. Run local verification:

```bash
python -m pip install -e .
python -m unittest discover -s tests -p 'test_*.py' -v
python -m prompt_guard.benchmark
npm ci
npm run lint
npm test
npm run benchmark
npm pack --dry-run
python -m build --outdir python-dist
make package-check
```

5. Confirm package contents do not include tests, caches, or generated development artifacts.
6. Confirm `benchmarks/cases.json` and `src_py/prompt_guard/data/cases.json` match.
7. Create a GitHub release tag.
8. Run the Release workflow with the desired publish targets.
