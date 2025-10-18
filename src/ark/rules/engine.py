"""Simple rule evaluation engine for Arkkeeper."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .parser import Rule, RuleParser


SAFE_GLOBALS = {"__builtins__": {}}
SAFE_FUNCTIONS = {
    "len": len,
    "any": any,
    "all": all,
    "min": min,
    "max": max,
    "sum": sum,
}


@dataclass
class EvaluationResult:
    """Result returned when a rule matches metadata."""

    severity: str
    rule: str
    message: str
    weight: int
    fix: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "rule": self.rule,
            "message": self.message,
            "weight": self.weight,
            "fix": self.fix,
        }


class RuleEngine:
    """Evaluate metadata against declarative rules."""

    def __init__(self, rules: Iterable[Rule]) -> None:
        self.rules = list(rules)

    @classmethod
    def from_files(cls, paths: Iterable[Path]) -> "RuleEngine":
        rules = RuleParser.load_from_paths(paths)
        return cls(rules)

    def evaluate(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        metadata = dict(finding.get("metadata", {}))
        metadata.update({
            "path": finding.get("path"),
            "category": finding.get("category"),
        })
        metadata.update(SAFE_FUNCTIONS)

        matches: List[Dict[str, Any]] = []
        for rule in self.rules:
            if rule.category != finding.get("category"):
                continue
            try:
                result = eval(rule.condition, SAFE_GLOBALS, metadata)
            except Exception:
                continue
            if result:
                matches.append(
                    EvaluationResult(
                        severity=rule.severity,
                        rule=rule.rule_id,
                        message=rule.description,
                        weight=rule.weight,
                        fix=rule.remediation,
                    ).to_dict()
                )
        return matches

    def apply(self, findings: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
        for category_findings in findings.values():
            for finding in category_findings:
                existing_rules = {issue.get("rule") for issue in finding.get("findings", [])}
                matches = self.evaluate(finding)
                if matches:
                    enriched = [m for m in matches if m.get("rule") not in existing_rules]
                    if enriched:
                        finding.setdefault("findings", []).extend(enriched)
        return findings
