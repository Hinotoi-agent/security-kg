# Contributing to VulnWeave

Thanks for helping improve VulnWeave.

## Development setup

```bash
git clone https://github.com/Hinotoi-agent/vulnweave
cd vulnweave
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Checks

Run the same core checks as CI:

```bash
python -m pytest -q
python -m ruff check src tests examples
python -m compileall -q src tests examples
```

Useful smoke checks:

```bash
vulnweave map examples/remote_resume_drift --out /tmp/vulnweave-smoke
vulnweave candidates /tmp/vulnweave-smoke
vulnweave vault-graph --vault examples/vault --dry-run
vulnweave doctor --repo examples/remote_resume_drift --vault examples/vault
```

## Detector contributions

Good detector PRs are small and invariant-driven. Please include:

- the vulnerable pattern and safe pattern
- the trust boundary crossed
- source/sink examples
- false-positive considerations
- one fixture and one regression test
- expected candidate evidence and proof strategy

Prefer one focused detector per PR rather than a broad noisy scanner.

## Public examples

Examples, tests, and docs must use dummy data only. Do not commit real vault paths, private repo names, tokens, emails, disclosure drafts, or unreleased finding details.
