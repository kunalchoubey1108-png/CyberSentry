"""Deterministic detection rules with a registry.

Every rule has the signature
``detect(events, config, assets=None) -> list[RuleMatch]`` and is
independently testable; ``run_all_rules`` runs the full registry in rule
order. Rules fully determine detections (AGENTS.md rule 1) — the LLM never
adds, removes, or modifies a match.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from ..schema import Asset, Event
from .base import RuleMatch
from .config import RuleConfig, load_config
from .r1_login_burst import detect as r1_detect
from .r2_suspicious_privilege import detect as r2_detect
from .r3_password_spray import detect as r3_detect
from .r4_offhours_elevated import detect as r4_detect

__all__ = [
    "REGISTRY",
    "RULES",
    "RuleConfig",
    "RuleMatch",
    "load_config",
    "run_all_rules",
]

# Registry in evaluation order. R2 reuses R1 internally (see r2 module docstring).
RuleFn = Callable[..., list[RuleMatch]]

RULES: tuple[tuple[str, RuleFn], ...] = (
    ("R1", r1_detect),
    ("R2", r2_detect),
    ("R3", r3_detect),
    ("R4", r4_detect),
)

REGISTRY: Mapping[str, RuleFn] = {rule_id: fn for rule_id, fn in RULES}


def run_all_rules(
    events: Sequence[Event],
    config: RuleConfig | None = None,
    assets: Mapping[str, Asset] | None = None,
) -> list[RuleMatch]:
    """Run every registered rule over ``events``; matches in rule order."""
    if config is None:
        config = load_config()
    if assets is None:
        from ..ingest import load_assets  # deferred: keeps import graph simple

        assets = load_assets()
    matches: list[RuleMatch] = []
    for _rule_id, rule in RULES:
        matches.extend(rule(events, config, assets))
    return matches
