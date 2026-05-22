from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from security_kg.schema import Edge, Graph, Node

META_FILE = "meta.json"
NODES_FILE = "nodes.jsonl"
EDGES_FILE = "edges.jsonl"


def graph_to_dict(graph: Graph) -> dict[str, Any]:
    """Serialize a graph to a JSON-compatible dictionary."""
    return {
        "root": str(graph.root),
        "nodes": [asdict(node) for node in graph.nodes],
        "edges": [asdict(edge) for edge in graph.edges],
    }


def graph_from_dict(data: dict[str, Any]) -> Graph:
    """Load a graph from a dictionary produced by graph_to_dict."""
    graph = Graph(root=Path(data["root"]))
    graph.nodes = [Node(**node) for node in data.get("nodes", [])]
    graph.edges = [Edge(**edge) for edge in data.get("edges", [])]
    return graph


def write_graph_jsonl(graph: Graph, out_dir: str | Path) -> Path:
    """Write graph metadata, nodes, and edges as JSON/JSONL files."""
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)

    (target / META_FILE).write_text(
        json.dumps({"root": str(graph.root)}, indent=2, sort_keys=True) + "\n",
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
