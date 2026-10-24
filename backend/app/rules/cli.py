"""CLI: run the rule registry over a log file and print a match summary.

Usage (from backend/):

    python -m app.rules.cli                       # default: sample_attacks.csv
    python -m app.rules.cli --events ../data/sample_benign.csv
"""

from __future__ import annotations

import argparse
from pathlib import Path

from ..ingest import DEFAULT_ASSETS_PATH, load_assets, load_events
from .config import CONFIG_PATH, load_config
from . import REGISTRY, run_all_rules

DEFAULT_EVENTS_PATH = Path(__file__).resolve().parents[3] / "data" / "sample_attacks.csv"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m app.rules.cli",
        description="Run deterministic detection rules over a log file.",
    )
    parser.add_argument("--events", type=Path, default=DEFAULT_EVENTS_PATH)
    parser.add_argument("--assets", type=Path, default=DEFAULT_ASSETS_PATH)
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    args = parser.parse_args(argv)

    events, rejected = load_events(args.events)
    assets = load_assets(args.assets)
    config = load_config(args.config)
    matches = run_all_rules(events, config, assets)

    print(f"events:  {len(events)} ingested, {len(rejected)} rejected  ({args.events.name})")
    print(f"assets:  {len(assets)} hosts   config: {args.config.name}")
    print("-" * 72)
    for match in matches:
        entity_text = ", ".join(f"{k}={v}" for k, v in sorted(match.entities.items()))
        print(f"[{match.rule_id} sev={match.severity}] {entity_text}")
        print(f"    events: {', '.join(match.matched_event_ids)}")
        print(f"    {match.reason}")
    print("-" * 72)
    by_rule: dict[str, int] = {}
    for match in matches:
        by_rule[match.rule_id] = by_rule.get(match.rule_id, 0) + 1
    counts = ", ".join(f"{rule_id}={by_rule.get(rule_id, 0)}" for rule_id in REGISTRY)
    print(f"matches: {len(matches)}  ({counts})")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
