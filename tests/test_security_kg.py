from pathlib import Path

from security_kg.extract import map_repo
from security_kg.invariants import find_candidates
from security_kg.io import read_graph_jsonl, write_graph_jsonl
from security_kg.report import render_candidate_markdown


def test_maps_command_registry_and_session_scope(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "registry.py"
    source.write_text(
        """
from app import CommandSpec

COMMANDS = [
    CommandSpec(
        name='/resume',
        handler='resume_command',
        remote_invocable=True,
        remote_admin_opt_in=False,
    )
]

def build_session_key(platform, chat, thread, sender):
    return f"{platform}:{chat}:{thread}:{sender}"

def resume_command(backend, session_id):
    return backend.load_by_id(session_id)
""".strip(),
        encoding="utf-8",
    )

    graph = map_repo(repo)

    commands = [node for node in graph.nodes if node.kind == "command"]
    assert len(commands) == 1
    assert commands[0].name == "/resume"
    assert commands[0].attrs["remote_invocable"] is True
    assert commands[0].attrs["remote_admin_opt_in"] is False

    assert any(
        node.kind == "session_scope" and "sender" in node.attrs["parts"]
        for node in graph.nodes
    )
    assert any(node.kind == "sink" and node.name == "load_by_id" for node in graph.nodes)


def test_flags_remote_resume_direct_load_drift(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    write_vulnerable_fixture(repo)

    graph = map_repo(repo)
    candidates = find_candidates(graph)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.pattern == "remote-command-session-direct-load"
    assert candidate.severity_hint == "high"
    assert "/resume" in candidate.title
    assert "remote chat sender" in candidate.boundary
    assert "load_by_id" in "\n".join(candidate.evidence)

    markdown = render_candidate_markdown(candidate)
    assert "## Candidate" in markdown
    assert "Violated invariant" in markdown
    assert "Proof strategy" in markdown
    assert "Seed one actor" in markdown


def test_round_trips_graph_jsonl_and_finds_candidates(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    write_vulnerable_fixture(repo)

    graph_dir = tmp_path / "graph"
    original = map_repo(repo)
    write_graph_jsonl(original, graph_dir)
    loaded = read_graph_jsonl(graph_dir)

    assert loaded.root == original.root
    assert [node.id for node in loaded.nodes] == [node.id for node in original.nodes]
    assert [edge.target for edge in loaded.edges] == [edge.target for edge in original.edges]
    assert find_candidates(loaded)[0].pattern == "remote-command-session-direct-load"


def write_vulnerable_fixture(repo: Path) -> None:
    (repo / "gateway.py").write_text(
        """
from app import CommandSpec

CommandSpec(name='/resume', handler='resume_command', remote_invocable=True)

def session_key(platform, chat, thread, sender):
    return f"{platform}:{chat}:{thread}:{sender}"

def resume_command(backend, session_id):
    return backend.load_by_id(session_id)
""".strip(),
        encoding="utf-8",
    )
