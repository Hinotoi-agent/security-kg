from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from security_kg.schema import Edge, Graph, Node

COMMAND_FACTORY_NAMES = {"CommandSpec", "Command", "SlashCommand"}
SENSITIVE_CALL_NAMES = {"load_by_id", "get_by_id", "read_by_id", "resume", "summary"}
SESSION_SCOPE_PARTS = {"platform", "chat", "thread", "sender", "user", "tenant", "session"}


def map_repo(root: str | Path) -> Graph:
    """Map a repository into a small security-relevant graph."""
    repo_root = Path(root).resolve()
    graph = Graph(root=repo_root)
    for path in sorted(repo_root.rglob("*.py")):
        if any(part in {".venv", "venv", "__pycache__", ".git"} for part in path.parts):
            continue
        _map_python_file(graph, repo_root, path)
    return graph


def _map_python_file(graph: Graph, repo_root: Path, path: Path) -> None:
    rel = path.relative_to(repo_root).as_posix()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
    except SyntaxError:
        return

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            graph.add_node(
                Node(
                    id=f"function:{rel}:{node.name}:{node.lineno}",
                    kind="function",
                    name=node.name,
                    file=rel,
                    line=node.lineno,
                    attrs={"docstring": ast.get_docstring(node)},
                )
            )
            _maybe_add_session_scope(graph, rel, node)

        if isinstance(node, ast.Call):
            command = _command_from_call(rel, node)
            if command is not None:
                graph.add_node(command)

            sink = _sink_from_call(rel, node)
            if sink is not None:
                graph.add_node(sink)
                graph.add_edge(Edge(source=f"file:{rel}", target=sink.id, kind="evidence"))


def _command_from_call(rel: str, node: ast.Call) -> Node | None:
    name = _call_name(node.func)
    if name not in COMMAND_FACTORY_NAMES:
        return None

    attrs: dict[str, Any] = {}
    command_name = None
    for keyword in node.keywords:
        if keyword.arg is None:
            continue
        value = _literal(keyword.value)
        attrs[keyword.arg] = value
        if keyword.arg in {"name", "command", "trigger"} and isinstance(value, str):
            command_name = value

    if command_name is None and node.args:
        first = _literal(node.args[0])
        if isinstance(first, str):
            command_name = first

    if not command_name:
        return None

    attrs.setdefault("remote_invocable", False)
    attrs.setdefault("remote_admin_opt_in", False)
    return Node(
        id=f"command:{rel}:{command_name}:{node.lineno}",
        kind="command",
        name=command_name,
        file=rel,
        line=node.lineno,
        attrs=attrs,
    )


def _sink_from_call(rel: str, node: ast.Call) -> Node | None:
    name = _call_name(node.func)
    if name not in SENSITIVE_CALL_NAMES:
        return None
    return Node(
        id=f"sink:{rel}:{name}:{node.lineno}:{node.col_offset}",
        kind="sink",
        name=name,
        file=rel,
        line=node.lineno,
        attrs={"capability": _capability_for_sink(name)},
    )


def _maybe_add_session_scope(
    graph: Graph,
    rel: str,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> None:
    parts: set[str] = set()
    arg_names = {arg.arg for arg in node.args.args}
    if "key" in node.name or "scope" in node.name or "session" in node.name:
        parts |= arg_names & SESSION_SCOPE_PARTS

    for child in ast.walk(node):
        if isinstance(child, ast.JoinedStr):
            text = ast.unparse(child) if hasattr(ast, "unparse") else ""
            parts |= {part for part in SESSION_SCOPE_PARTS if part in text}
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            parts |= {part for part in SESSION_SCOPE_PARTS if part in child.value}

    if len(parts) >= 2 and ({"sender", "user", "tenant"} & parts):
        graph.add_node(
            Node(
                id=f"session_scope:{rel}:{node.name}:{node.lineno}",
                kind="session_scope",
                name=node.name,
                file=rel,
                line=node.lineno,
                attrs={"parts": sorted(parts)},
            )
        )


def _call_name(func: ast.expr) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _literal(node: ast.AST) -> Any:
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        return None


def _capability_for_sink(name: str) -> str:
    if name in {"load_by_id", "get_by_id", "read_by_id"}:
        return "direct_object_load"
    if name in {"resume", "summary"}:
        return "session_control_plane"
    return "sensitive_operation"
