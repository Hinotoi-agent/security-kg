from __future__ import annotations

from pathlib import Path

from security_kg.cli import main
from security_kg.extract import map_repo
from security_kg.invariants import find_candidates
from security_kg.io import write_graph_jsonl
from security_kg.vault.export import export_candidate_note, finding_note_filename


def write_vulnerable_fixture(repo: Path) -> None:
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


def test_exports_candidate_to_obsidian_finding_note(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write_vulnerable_fixture(repo)
    candidate = find_candidates(map_repo(repo))[0]
    vault = tmp_path / "vault"

    path = export_candidate_note(
        candidate,
        vault=vault,
        target="Target - Example App",
        repo_url="https://github.com/example-org/example-repo",
        status="draft",
    )

    assert path == vault / "03 - Findings" / finding_note_filename(candidate, repo_url="https://github.com/example-org/example-repo")
    text = path.read_text(encoding="utf-8")
    assert "type: finding" in text
    assert "status: draft" in text
    assert "severity: High" in text
    assert "target: Target - Example App" in text
    assert "repo: https://github.com/example-org/example-repo" in text
    assert "pattern: remote-command-session-direct-load" in text
    assert "security-kg" in text
    assert "## Candidate summary" in text
    assert "## Evidence" in text
    assert "gateway.py" in text
    assert "## Proof strategy" in text
    assert "Seed one actor" in text
    assert "## Duplicate check" in text


def test_cli_export_finding_writes_selected_candidate_note(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write_vulnerable_fixture(repo)
    graph_dir = tmp_path / "graph"
    write_graph_jsonl(map_repo(repo), graph_dir)
    candidate = find_candidates(map_repo(repo))[0]
    vault = tmp_path / "vault"

    assert main(
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
    ) == 0

    notes = list((vault / "03 - Findings").glob("*.md"))
    assert len(notes) == 1
    text = notes[0].read_text(encoding="utf-8")
    assert f"candidate_id: {candidate.id}" in text
    assert "[[Target - Example App]]" in text
