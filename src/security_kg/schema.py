from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

NodeKind = Literal["command", "function", "sink", "session_scope"]
EdgeKind = Literal["defined_in", "calls", "evidence"]


@dataclass(frozen=True)
class Node:
    id: str
    kind: NodeKind
    name: str
    file: str
    line: int
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    kind: EdgeKind
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class Graph:
    root: Path
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)

    def add_node(self, node: Node) -> None:
        self.nodes.append(node)

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)


@dataclass(frozen=True)
class Candidate:
    id: str
    title: str
    pattern: str
    severity_hint: str
    boundary: str
    violated_invariant: str
    graph_path: list[str]
    evidence: list[str]
    proof_strategy: list[str]
