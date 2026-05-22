from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security_kg.schema import Edge, Graph, Node

META_FILE = "meta.json"
NODES_FILE = "nodes.jsonl"
EDGES_FILE = "edges.jsonl"
GRAPH_SCHEMA_VERSION = "vulnweave.graph.v1"
CANDIDATE_SCHEMA_VERSION = "vulnweave.candidates.v1"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def graph_to_dict(graph: Graph) -> dict[str, Any]:
    """Serialize a graph to a JSON-compatible dictionary."""
    return {
        "schema_version": GRAPH_SCHEMA_VERSION,
        "generated_at": utc_now_iso(),
        "source": {"root": str(graph.root), "tool": "vulnweave"},
        "root": str(graph.root),  # compatibility with early MVP output
        "nodes": [asdict(node) for node in graph.nodes],
        "edges": [asdict(edge) for edge in graph.edges],
    }


def candidates_to_dict(candidates: list[Any], source: str | Path | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {
        "schema_version": CANDIDATE_SCHEMA_VERSION,
        "generated_at": utc_now_iso(),
        "candidates": [asdict(candidate) for candidate in candidates],
    }
    if source is not None:
        data["source"] = str(source)
    return data


def graph_from_dict(data: dict[str, Any]) -> Graph:
    """Load a graph from a dictionary produced by graph_to_dict."""
    root = data.get("root") or data.get("source", {}).get("root")
    graph = Graph(root=Path(root))
    graph.nodes = [Node(**node) for node in data.get("nodes", [])]
    graph.edges = [Edge(**edge) for edge in data.get("edges", [])]
    return graph


def write_graph_jsonl(graph: Graph, out_dir: str | Path) -> Path:
    """Write graph metadata, nodes, and edges as JSON/JSONL files."""
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)

    (target / META_FILE).write_text(
        json.dumps(
            {
                "schema_version": GRAPH_SCHEMA_VERSION,
                "generated_at": utc_now_iso(),
                "root": str(graph.root),
                "tool": "vulnweave",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _write_jsonl(target / NODES_FILE, (asdict(node) for node in graph.nodes))
    _write_jsonl(target / EDGES_FILE, (asdict(edge) for edge in graph.edges))
    return target


def read_graph_jsonl(in_dir: str | Path) -> Graph:
    """Read a graph written by write_graph_jsonl."""
    source = Path(in_dir)
    meta_path = source / META_FILE
    if not meta_path.exists():
        raise FileNotFoundError(f"missing graph metadata: {meta_path}")

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    graph = Graph(root=Path(meta["root"]))
    graph.nodes = [Node(**item) for item in _read_jsonl(source / NODES_FILE)]
    graph.edges = [Edge(**item) for item in _read_jsonl(source / EDGES_FILE)]
    return graph


def is_graph_dir(path: str | Path) -> bool:
    source = Path(path)
    return (source / META_FILE).exists() and (source / NODES_FILE).exists()


def _write_jsonl(path: Path, rows: Any) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows
