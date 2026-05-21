PYTHON ?= python3

.PHONY: setup test test-python test-ts lint benchmark benchmark-python benchmark-ts build build-ts build-python package-check audit clean

setup:
	$(PYTHON) -m pip install -e .
	npm ci

test: test-python test-ts

test-python:
	PYTHONPATH=src_py $(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

test-ts:
	npm test

lint:
	npm run lint

benchmark: benchmark-python benchmark-ts

benchmark-python:
	PYTHONPATH=src_py $(PYTHON) -m prompt_guard.benchmark --cases benchmarks/cases.json

benchmark-ts:
	npm run benchmark -- --cases benchmarks/cases.json

build: build-ts build-python

build-ts:
	npm run build

build-python:
	$(PYTHON) -m build --outdir python-dist

package-check:
	npm pack --dry-run

audit:
	npm audit --audit-level=moderate

clean:
	rm -rf dist dist-test python-dist build *.egg-info
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	find . -name '*.py[cod]' -delete
