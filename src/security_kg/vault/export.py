from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from security_kg.schema import Candidate

DEFAULT_FINDINGS_DIR = "03 - Findings"


def export_candidate_note(
    candidate: Candidate,
    *,
    vault: Path,
    target: str,
    repo_url: str = "",
    findings_dir: str = DEFAULT_FINDINGS_DIR,
    status: str = "draft",
) -> Path:
    """Write a security candidate as an Obsidian finding note."""
    output_dir = vault / findings_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / finding_note_filename(candidate, repo_url=repo_url)
    path.write_text(
        render_candidate_note(candidate, target=target, repo_url=repo_url, status=status),
        encoding="utf-8",
    )
    return path


def finding_note_filename(candidate: Candidate, *, repo_url: str = "") -> str:
    repo = _repo_slug(repo_url)
    title = _slugify(candidate.title)
    if repo:
        title = f"{repo}-{title}"
    return f"Finding - {title}.md"


def render_candidate_note(
    candidate: Candidate,
    *,
    target: str,
    repo_url: str = "",
    status: str = "draft",
) -> str:
    severity = candidate.severity_hint.capitalize()
    lines = [
        "---",
        "type: finding",
        f"status: {status}",
        f"severity: {severity}",
        f"target: {target}",
        f"repo: {repo_url}" if repo_url else "repo:",
        f"pattern: {candidate.pattern}",
        f"candidate_id: {candidate.id}",
        "tags:",
        "  - security-kg",
        f"  - {_slugify(candidate.pattern)}",
        "generated_by: security-kg",
        "---",
        "",
        f"# {candidate.title}",
        "",
        f"Target: [[{target}]]",
        "",
        "## Candidate summary",
        "",
        f"- Pattern: `{candidate.pattern}`",
        f"- Severity hint: `{candidate.severity_hint}`",
        f"- Boundary: {candidate.boundary}",
        "",
        "## Violated invariant",
        "",
        candidate.violated_invariant,
        "",
        "## Graph path",
        "",
    ]
    lines.extend(f"- {step}" for step in candidate.graph_path)
    lines.extend(["", "## Evidence", ""])
    lines.extend(f"- {item}" for item in candidate.evidence)
    lines.extend(["", "## Proof strategy", ""])
    lines.extend(f"- {step}" for step in candidate.proof_strategy)
    lines.extend(
        [
            "",
            "## Duplicate check",
            "",
            "- [ ] Search existing findings by target, pattern, CWE, and sink/capability.",
            "- [ ] Check sibling PRs and maintainer comments for overlapping fixes.",
            "- [ ] Confirm this is not already covered by an existing disclosure or merged PR.",
            "",
            "## Local reproduction notes",
            "",
            "TODO",
            "",
            "## Patch notes",
            "",
            "TODO",
            "",
            "## Disclosure / PR",
            "",
            "TODO",
        ]
    )
    return "\n".join(lines) + "\n"


def _repo_slug(repo_url: str) -> str:
    if not repo_url:
        return ""
    parsed = urlparse(repo_url)
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) >= 2:
        return _slugify(f"{parts[0]}-{parts[1]}")
    return _slugify(repo_url)


def _slugify(value: str) -> str:
    lower = value.strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "-", lower)
    return slug.strip("-") or "candidate"
