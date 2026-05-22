from __future__ import annotations

from pathlib import Path

from security_kg.io import EDGES_FILE, META_FILE, NODES_FILE, is_graph_dir


def run_doctor(
    repo: str | Path | None = None,
    graph: str | Path | None = None,
    vault: str | Path | None = None,
) -> tuple[int, list[str]]:
    lines: list[str] = ["VulnWeave doctor"]
    ok = True

    if repo is not None:
        repo_path = Path(repo).expanduser().resolve()
        if repo_path.exists() and repo_path.is_dir():
            lines.append(f"[ok] repo exists: {repo_path}")
        else:
            ok = False
            lines.append(f"[fail] repo does not exist or is not a directory: {repo_path}")

    if graph is not None:
        graph_path = Path(graph).expanduser().resolve()
        if is_graph_dir(graph_path):
            lines.append(f"[ok] graph directory looks valid: {graph_path}")
        else:
            ok = False
            lines.append(
                f"[fail] graph directory is missing {META_FILE} or {NODES_FILE}: {graph_path}"
            )
        for name in (META_FILE, NODES_FILE, EDGES_FILE):
            marker = "ok" if (graph_path / name).exists() else "warn"
            lines.append(f"[{marker}] {name}: {graph_path / name}")

    if vault is not None:
        vault_path = Path(vault).expanduser().resolve()
        if vault_path.exists() and vault_path.is_dir():
            lines.append(f"[ok] vault exists: {vault_path}")
        else:
            ok = False
            lines.append(f"[fail] vault does not exist or is not a directory: {vault_path}")
        for directory in ("03 - Findings", "02 - Targets", "99 - Graph"):
            path = vault_path / directory
            marker = "ok" if path.exists() else "warn"
            lines.append(f"[{marker}] vault directory {directory}: {path}")

    if repo is None and graph is None and vault is None:
        lines.append("[ok] CLI is importable. Pass --repo, --graph, or --vault for path checks.")

    return (0 if ok else 1), lines
