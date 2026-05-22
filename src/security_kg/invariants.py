from __future__ import annotations

from security_kg.schema import Candidate, Graph, Node

CONTROL_PLANE_COMMAND_NAMES = {"/resume", "/summary", "/debug", "/config", "/shell", "/tools"}
DIRECT_LOAD_SINKS = {"load_by_id", "get_by_id", "read_by_id"}


def find_candidates(graph: Graph) -> list[Candidate]:
    candidates: list[Candidate] = []
    commands = [node for node in graph.nodes if node.kind == "command"]
    sinks = [node for node in graph.nodes if node.kind == "sink"]
    scopes = [node for node in graph.nodes if node.kind == "session_scope"]

    for command in commands:
        if _is_remote_control_plane_command(command) and _has_direct_load_sink(sinks) and scopes:
            sink = next(node for node in sinks if node.name in DIRECT_LOAD_SINKS)
            scope = scopes[0]
            candidates.append(
                Candidate(
                    id=_candidate_id(command, sink),
                    title=f"Remote {command.name} can reach direct session/object load",
                    pattern="remote-command-session-direct-load",
                    severity_hint="high",
                    boundary="remote chat sender -> command dispatcher -> session/object restore",
                    violated_invariant=(
                        "Remote session-scoped actors must not invoke global restore/list/read "
                        "operations without re-authorizing the same sender/session scope."
                    ),
                    graph_path=[
                        "remote chat sender",
                        f"command {command.name} ({command.file}:{command.line})",
                        f"sink {sink.name} ({sink.file}:{sink.line})",
                    ],
                    evidence=[
                        f"{command.file}:{command.line} registers {command.name} with "
                        f"remote_invocable={command.attrs.get('remote_invocable')!r}",
                        f"{scope.file}:{scope.line} builds scoped session key parts "
                        f"{', '.join(scope.attrs['parts'])}",
                        (
                            f"{sink.file}:{sink.line} calls {sink.name}, "
                            "a direct object/session load sink"
                        ),
                    ],
                    proof_strategy=[
                        "Seed one actor's session/object with a unique marker.",
                        f"Invoke {command.name} as a different remote actor.",
                        "Assert the first actor's ID/marker is not listed, loaded, or summarized.",
                        "Assert the direct load sink is not reached for the wrong actor scope.",
                    ],
                )
            )
    return candidates


def _is_remote_control_plane_command(command: Node) -> bool:
    if command.attrs.get("remote_invocable") is not True:
        return False
    if command.attrs.get("remote_admin_opt_in") is True:
        return False
    if command.name in CONTROL_PLANE_COMMAND_NAMES:
        return True
    lower_name = command.name.lower()
    return any(word in lower_name for word in ("resume", "summary", "session", "debug"))


def _has_direct_load_sink(sinks: list[Node]) -> bool:
    return any(node.name in DIRECT_LOAD_SINKS for node in sinks)


def _candidate_id(command: Node, sink: Node) -> str:
    slug = command.name.strip("/").replace("/", "-") or "command"
    return f"{slug}-{sink.name}-{command.line}"
