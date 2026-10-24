"""Typed access to rule thresholds in backend/config.yaml.

Deterministic rules read every threshold from config (AGENTS.md rule 1);
the LLM never supplies or overrides these values. Missing keys fall back to
the documented defaults below; malformed values fail loudly.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, Mapping

import yaml

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config.yaml"

_MIN_HOUR = 0
_MAX_HOUR = 23
_MIN_SEVERITY = 1
_MAX_SEVERITY = 10


@dataclass(frozen=True)
class RuleConfig:
    """Thresholds for rules R1-R4, loaded from config.yaml."""

    # R1: failure burst then success.
    login_burst_failure_threshold: int = 5
    login_burst_failure_window_seconds: int = 600
    login_burst_success_window_seconds: int = 900
    login_burst_severity: int = 8
    # R2: privileged event shortly after a suspicious login.
    privilege_window_seconds: int = 1800
    privilege_severity: int = 9
    # R3: password spray.
    spray_distinct_user_threshold: int = 5
    spray_window_seconds: int = 600
    spray_severity: int = 7
    # R4: elevated access off-hours on critical hosts.
    offhours_start_hour: int = 8
    offhours_end_hour: int = 20
    offhours_min_criticality: int = 4
    offhours_severity: int = 6


# config.yaml block -> {yaml key: RuleConfig field}
_BLOCKS: dict[str, dict[str, str]] = {
    "r1_failed_login_burst": {
        "failure_threshold": "login_burst_failure_threshold",
        "failure_window_seconds": "login_burst_failure_window_seconds",
        "success_window_seconds": "login_burst_success_window_seconds",
        "severity": "login_burst_severity",
    },
    "r2_suspicious_privilege": {
        "window_seconds": "privilege_window_seconds",
        "severity": "privilege_severity",
    },
    "r3_password_spray": {
        "distinct_user_threshold": "spray_distinct_user_threshold",
        "window_seconds": "spray_window_seconds",
        "severity": "spray_severity",
    },
    "r4_offhours_elevated": {
        "start_hour": "offhours_start_hour",
        "end_hour": "offhours_end_hour",
        "min_criticality": "offhours_min_criticality",
        "severity": "offhours_severity",
    },
}


def _require_int(block: str, key: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"config: rules.{block}.{key} must be an integer, got {value!r}")
    return value


def load_config(path: Path = CONFIG_PATH) -> RuleConfig:
    """Load rule thresholds from ``path``; missing file/keys -> defaults."""
    defaults = RuleConfig()
    if not path.exists():
        return defaults
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, Mapping):
        raise ValueError(f"config: {path} must contain a YAML mapping")
    rules = raw.get("rules", {})
    if not isinstance(rules, Mapping):
        raise ValueError(f"config: {path}: 'rules' must be a mapping")

    values: dict[str, int] = {}
    for block_name, key_map in _BLOCKS.items():
        block = rules.get(block_name, {})
        if block is None:
            continue
        if not isinstance(block, Mapping):
            raise ValueError(f"config: rules.{block_name} must be a mapping")
        for yaml_key, field_name in key_map.items():
            if yaml_key in block:
                values[field_name] = _require_int(block_name, yaml_key, block[yaml_key])

    _validate(values)
    known = {field.name for field in fields(RuleConfig)}
    return RuleConfig(**{k: v for k, v in values.items() if k in known})


def _validate(values: Mapping[str, int]) -> None:
    for name, value in values.items():
        if name.endswith("_severity") and not _MIN_SEVERITY <= value <= _MAX_SEVERITY:
            raise ValueError(
                f"config: {name} must be between {_MIN_SEVERITY} and {_MAX_SEVERITY}, got {value}"
            )
        if name.startswith("offhours_") and name.endswith("_hour"):
            if not _MIN_HOUR <= value <= _MAX_HOUR:
                raise ValueError(f"config: {name} must be 0-23, got {value}")
    for name in ("login_burst_failure_threshold", "spray_distinct_user_threshold"):
        if name in values and values[name] < 2:
            raise ValueError(f"config: {name} must be >= 2, got {values[name]}")
