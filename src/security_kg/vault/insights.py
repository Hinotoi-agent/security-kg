from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from security_kg.schema import Graph, Node
from security_kg.vault.finding_graph import build_vault_graph


@dataclass
class VaultInsights:
    duplicate_clusters: list[list[str]] = field(default_factory=list)
    stale_drafts: list[str] = field(default_factory=list)
    missing_fields: dict[str, list[str]] = field(default_factory=dict)
    variant_opportunities: list[str] = field(default_factory=list)


def analyze_vault(
    vault: str | Path,
    findings_dir: str = "03 - Findings",
    targets_dir: str = "02 - Targets",
) -> VaultInsights:
    graph = build_vault_graph(Path(vault), findings_dir=findings_dir, targets_dir=targets_dir)
    return analyze_graph(graph)


def analyze_graph(graph: Graph) -> VaultInsights:
    findings = [node for node in graph.nodes if node.kind == "finding"]
    insights = VaultInsights()
    insights.duplicate_clusters = _duplicate_clusters(graph, findings)
    insights.missing_fields = _missing_fields(findings)
    insights.stale_drafts = [
        node.label
        for node in findings
        if str(node.attrs.get("status") or "").lower() in {"draft", "todo", "open"}
    ]
    insights.variant_opportunities = _variant_opportunities(graph, findings)
    return insights


def render_insights(insights: VaultInsights) -> str:
    lines = ["# VulnWeave Vault Insights", ""]
    lines.append("## Potential duplicate clusters")
    if insights.duplicate_clusters:
        for cluster in insights.duplicate_clusters:
            lines.append("- " + "; ".join(cluster))
    else:
        lines.append("- None detected")

    lines.extend(["", "## Draft/open findings", ""])
    if insights.stale_drafts:
        lines.extend(f"- {item}" for item in insights.stale_drafts)
    else:
        lines.append("- None detected")

    lines.extend(["", "## Findings missing useful fields", ""])
    if insights.missing_fields:
        for finding, fields in insights.missing_fields.items():
            lines.append(f"- {finding}: missing {', '.join(fields)}")
    else:
        lines.append("- None detected")

    lines.extend(["", "## Variant opportunities", ""])
    if insights.variant_opportunities:
        lines.extend(f"- {item}" for item in insights.variant_opportunities)
    else:
        lines.append("- None detected")
    return "\n".join(lines) + "\n"


def _duplicate_clusters(graph: Graph, findings: list[Node]) -> list[list[str]]:
    by_signature: dict[tuple[str, ...], list[str]] = {}
    for finding in findings:
        neighbors = _neighbor_labels(graph, finding.id, kinds={"repo", "cwe", "tag", "target"})
        signature = tuple(sorted(neighbors))
        if len(signature) >= 2:
            by_signature.setdefault(signature, []).append(finding.label)
    return [cluster for cluster in by_signature.values() if len(cluster) > 1]


def _missing_fields(findings: list[Node]) -> dict[str, list[str]]:
    required = ["status", "severity"]
    missing: dict[str, list[str]] = {}
    for finding in findings:
        fields = [field for field in required if not finding.attrs.get(field)]
        if fields:
            missing[finding.label] = fields
    return missing


def _variant_opportunities(graph: Graph, findings: list[Node]) -> list[str]:
    by_neighbor: dict[str, set[str]] = {}
    for finding in findings:
        for label in _neighbor_labels(graph, finding.id, kinds={"cwe", "tag", "repo", "target"}):
            by_neighbor.setdefault(label, set()).add(finding.label)
    opportunities = []
    for label, group in sorted(by_neighbor.items()):
        if len(group) >= 2:
            opportunities.append(f"{label}: {len(group)} related findings")
    return opportunities


def _neighbor_labels(graph: Graph, source_id: str, kinds: set[str]) -> set[str]:
    node_by_id = {node.id: node for node in graph.nodes}
    labels = set()
    for edge in graph.edges:
        if edge.source != source_id:
            continue
        target = node_by_id.get(edge.target)
        if target and target.kind in kinds:
            labels.add(target.label)
    return labels
