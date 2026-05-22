# security-kg

`security-kg` is a lightweight prototype for building intent-aware security knowledge graphs from source repositories.

The first milestone focuses on a narrow, high-signal workflow for source-code vulnerability review:

1. Map security-relevant repo facts into graph nodes.
2. Detect invariant violations such as remote command exposure plus direct session/object loads.
3. Render candidate reports with boundary, evidence, graph path, and proof strategy.

This is intentionally not a vulnerability oracle. It produces review candidates that still require local proof, duplicate checks, and maintainer-safe reporting.

## Current MVP

The initial Python extractor detects:

- command registrations such as `CommandSpec(name='/resume', remote_invocable=True)`
- session-scope construction that includes actor fields such as `sender`, `user`, or `tenant`
- direct object/session load sinks such as `load_by_id`, `get_by_id`, and `read_by_id`
- a first invariant: remote control-plane command plus scoped session intent plus global direct-load sink

## Usage

```bash
python -m security_kg.cli map /path/to/repo
python -m security_kg.cli candidates /path/to/repo
```

With an installed editable package:

```bash
pip install -e '.[dev]'
security-kg map /path/to/repo
security-kg candidates /path/to/repo
```

## Development

```bash
python3 -m pytest -q
python3 -m ruff check src tests
```

## Roadmap

- Add JSONL graph export/import.
- Add route/webhook extractors.
- Add list-filter/direct-load drift detection.
- Add bearer handle ownership checks for jobs, processes, sessions, and artifacts.
- Add deterministic proof-skeleton generation.
- Add vault-note/report templates for confirmed findings.
