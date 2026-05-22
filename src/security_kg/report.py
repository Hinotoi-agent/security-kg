from __future__ import annotations

from security_kg.schema import Candidate


def render_candidate_markdown(candidate: Candidate) -> str:
    evidence = "\n".join(f"- {item}" for item in candidate.evidence)
    path = "\n".join(f"{index}. {item}" for index, item in enumerate(candidate.graph_path, start=1))
    proof = "\n".join(f"- {item}" for item in candidate.proof_strategy)
    return f"""## Candidate: {candidate.title}

**Pattern:** `{candidate.pattern}`
**Severity hint:** {candidate.severity_hint}
**Boundary:** {candidate.boundary}

### Violated invariant

{candidate.violated_invariant}

### Graph path

{path}

### Evidence

{evidence}

### Proof strategy

{proof}
"""
