"""Shell history enumerator."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from .base import BaseEnumerator, EnumerationResult


PATTERNS = {
    "aws_secret": re.compile(r"AKIA[0-9A-Z]{16}"),
    "password_export": re.compile(r"export\s+[A-Z0-9_]*PASS[A-Z0-9_]*=", re.IGNORECASE),
    "token_assign": re.compile(r"(token|secret|key)=", re.IGNORECASE),
}


class ShellHistoryEnumerator(BaseEnumerator):
    """Inspect shell history for accidental secret disclosure."""

    category = "shell"

    def __init__(self, shell_rc: Path | None = None) -> None:
        super().__init__(shell_rc or Path.home())
        self.history_files = [
            self.root / ".bash_history",
            self.root / ".zsh_history",
        ]

    def iter_results(self) -> Iterable[EnumerationResult]:
        results: list[EnumerationResult] = []
        for history_path in self.history_files:
            if not history_path.exists():
                continue
            content = history_path.read_text(errors="ignore")
            metadata = {
                "line_count": len(content.splitlines()),
                "patterns": {
                    name: bool(pattern.search(content))
                    for name, pattern in PATTERNS.items()
                },
            }
            results.append(
                EnumerationResult(
                    id=f"shell_history_{history_path.name}",
                    category=self.category,
                    path=str(history_path),
                    metadata=metadata,
                    findings=[],
                )
            )
        return results


def scan_shell() -> list[dict]:
    return ShellHistoryEnumerator().scan()
