from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from security_kg.extract import map_repo
from security_kg.invariants import find_candidates
from security_kg.report import render_candidate_markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="security-kg",
        description="Build a lightweight security knowledge graph and flag review candidates.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    map_parser = subparsers.add_parser("map", help="Extract graph nodes from a repository")
    map_parser.add_argument("repo", type=Path)
    map_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of a text summary",
    )

    candidates_parser = subparsers.add_parser("candidates", help="Find invariant-backed candidates")
    candidates_parser.add_argument("repo", type=Path)
    candidates_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of Markdown",
    )

    args = parser.parse_args(argv)

    if args.command == "map":
        graph = map_repo(args.repo)
        if args.json:
            print(
                json.dumps(
                    {
                        "root": str(graph.root),
                        "nodes": [asdict(node) for node in graph.nodes],
                        "edges": [asdict(edge) for edge in graph.edges],
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print(f"Mapped {len(graph.nodes)} nodes and {len(graph.edges)} edges from {graph.root}")
        return 0

    if args.command == "candidates":
        graph = map_repo(args.repo)
        candidates = find_candidates(graph)
        if args.json:
            print(
                json.dumps(
                    [asdict(candidate) for candidate in candidates],
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            if not candidates:
                print("No candidates found.")
            for candidate in candidates:
                print(render_candidate_markdown(candidate))
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
