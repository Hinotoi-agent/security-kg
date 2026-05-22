from pathlib import Path

from security_kg.cli import main
from security_kg.extract import map_repo
from security_kg.invariants import find_candidates
from security_kg.io import write_graph_jsonl
from security_kg.vault.export import export_candidate_note


def test_export_candidate_to_obsidian_finding_note(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
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
    graph = map_repo(repo)
    candidate = find_candidates(graph)[0]
    vault = tmp_path / "vault"

    note = export_candidate_note(
        graph=graph,
        candidate_id=candidate.id,
        vault=vault,
        target="Target - Example App",
        repo_url="https://github.com/example-org/example-repo",
    )

    text = note.read_text(encoding="utf-8")
    assert note.name.startswith("Finding - Repo - Remote Resume")
    assert 'type: "finding"' in text
    assert 'target: "Target - Example App"' in text
    assert 'repo: "https://github.com/example-org/example-repo"' in text
    assert "## Duplicate check" in text
    assert "## Proof strategy" in text
    assert candidate.id in text


def test_cli_export_finding_from_graph_dir(tmp_path: Path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
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
    graph = map_repo(repo)
    graph_dir = tmp_path / "graph"
    write_graph_jsonl(graph, graph_dir)
    candidate = find_candidates(graph)[0]
    vault = tmp_path / "vault"

    assert (
        main(
            [
                "export-finding",
                str(graph_dir),
                "--candidate",
                candidate.id,
                "--vault",
                str(vault),
                "--target",
                "Target - Example App",
                "--repo-url",
                "https://github.com/example-org/example-repo",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out.strip()
    assert Path(out).exists()
