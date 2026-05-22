from pathlib import Path

from security_kg.cli import main
from security_kg.doctor import run_doctor
from security_kg.vault.insights import analyze_vault, render_insights


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_doctor_checks_repo_graph_and_vault(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    graph = tmp_path / "graph"
    graph.mkdir()
    write(graph / "meta.json", '{"root":"/tmp/example"}')
    write(graph / "nodes.jsonl", "")
    vault = tmp_path / "vault"
    (vault / "03 - Findings").mkdir(parents=True)

    code, lines = run_doctor(repo=repo, graph=graph, vault=vault)

    assert code == 0
    text = "\n".join(lines)
    assert "[ok] repo exists" in text
    assert "[ok] graph directory looks valid" in text
    assert "[ok] vault exists" in text


def test_cli_vault_insights_reports_duplicates_and_missing_fields(tmp_path: Path, capsys):
    vault = tmp_path / "vault"
    write(vault / "02 - Targets" / "Target - Example.md", "---\ntype: target\n---\n")
    for name in ("A", "B"):
        write(
            vault / "03 - Findings" / f"Finding - {name}.md",
            """---
type: finding
status: draft
severity: High
target: Target - Example
repo: https://github.com/example-org/example-repo
cwe: CWE-639
tags: [idor]
---
[[Target - Example]] CWE-639 https://github.com/example-org/example-repo/pull/1
""",
        )
    write(
        vault / "03 - Findings" / "Finding - Missing.md",
        """---
type: finding
target: Target - Example
---
[[Target - Example]]
""",
    )

    insights = analyze_vault(vault)
    rendered = render_insights(insights)
    assert insights.duplicate_clusters
    assert "Finding - Missing" in rendered

    assert main(["vault-insights", "--vault", str(vault)]) == 0
    out = capsys.readouterr().out
    assert "Potential duplicate clusters" in out
