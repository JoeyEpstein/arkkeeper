"""YAML rule parser for Arkkeeper."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List

import yaml


@dataclass
class Rule:
    """Represents a single evaluation rule."""

    rule_id: str
    category: str
    severity: str
    weight: int
    description: str
    condition: str
    remediation: str


class RuleParser:
    """Load YAML rules into Rule objects."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> List[Rule]:
        data = yaml.safe_load(self.path.read_text())
        rules_section: Dict[str, Dict] = data.get("rules", {}) if isinstance(data, dict) else {}
        rules: List[Rule] = []
        for rule_id, payload in rules_section.items():
            rules.append(
                Rule(
                    rule_id=rule_id,
                    category=payload.get("category", "generic"),
                    severity=payload.get("severity", "low"),
                    weight=int(payload.get("weight", 0)),
                    description=payload.get("description", ""),
                    condition=payload.get("condition", "False"),
                    remediation=payload.get("remediation", ""),
                )
            )
        return rules

    @staticmethod
    def load_from_paths(paths: Iterable[Path]) -> List[Rule]:
        rules: List[Rule] = []
        for path in paths:
            if path.exists():
                rules.extend(RuleParser(path).load())
        return rules
