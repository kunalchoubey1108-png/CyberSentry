"""Shared rule primitives: the match contract every detection rule returns.

Every alert traces to a rule ID and concrete event IDs (AGENTS.md rule 3):
a ``RuleMatch`` can never exist without both.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class RuleMatch(BaseModel):
    """One detection finding produced by a deterministic rule.

    ``severity`` is a 1-10 integer (not a score contribution — scoring lives
    in ``app.scoring``). ``matched_event_ids`` are the concrete events that
    produced the finding; ``entities`` names the involved user / src_ip /
    host so downstream correlation can group matches into incidents.
    """

    model_config = ConfigDict(strict=True)

    rule_id: str
    severity: int = Field(ge=1, le=10)
    matched_event_ids: list[str]
    reason: str
    entities: dict[str, str]
