"""PyPI credential enumerator."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .base import BaseEnumerator, EnumerationResult


class PyPIEnumerator(BaseEnumerator):
    """Inspect ~/.pypirc for saved tokens."""

    category = "pypi"

    def __init__(self, pypirc_path: Path | None = None) -> None:
        super().__init__(pypirc_path or Path.home())
        self.pypirc = self.root / ".pypirc"

    def iter_results(self) -> Iterable[EnumerationResult]:
        if not self.pypirc.exists():
            return []

        content = self.pypirc.read_text(errors="ignore")
        metadata = {
            "has_password": "password" in content,
            "index_servers": [line.split("=", 1)[1].strip() for line in content.splitlines() if line.strip().startswith("index-servers")],
        }
        return [
            EnumerationResult(
                id="pypirc",
                category=self.category,
                path=str(self.pypirc),
                metadata=metadata,
                findings=[],
            )
        ]


def scan_pypi() -> list[dict]:
    return PyPIEnumerator().scan()
