"""Base classes and helpers for Arkkeeper enumerators."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List


@dataclass
class EnumerationResult:
    """Normalized result returned by enumerators."""

    id: str
    category: str
    path: str
    metadata: Dict[str, Any]
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary expected by CLI."""
        return {
            "id": self.id,
            "category": self.category,
            "path": self.path,
            "metadata": self.metadata,
            "findings": list(self.findings),
        }


class BaseEnumerator:
    """Convenience base class for file-system enumerators."""

    category: str = "generic"

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or Path.home()

    def scan(self) -> List[Dict[str, Any]]:
        """Return serialized results ready for downstream processing."""
        results = [result.to_dict() for result in self.iter_results()]
        return results

    def iter_results(self) -> Iterable[EnumerationResult]:  # pragma: no cover - abstract
        """Enumerate resources and yield structured results."""
        raise NotImplementedError
