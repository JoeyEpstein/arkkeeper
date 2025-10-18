"""GitHub CLI token enumerator."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .base import BaseEnumerator, EnumerationResult


class GitHubEnumerator(BaseEnumerator):
    """Inspect gh CLI configuration for stored PATs."""

    category = "github"

    def __init__(self, gh_dir: Path | None = None) -> None:
        super().__init__(gh_dir or Path.home() / ".config" / "gh")
        self.tokens = self.root / "hosts.yml"

    def iter_results(self) -> Iterable[EnumerationResult]:
        if not self.tokens.exists():
            return []

        metadata = {
            "token_file_size": self.tokens.stat().st_size,
        }

        # hosts.yml is YAML but to avoid dependency we parse basic content
        token_lines = [line for line in self.tokens.read_text().splitlines() if "oauth_token" in line]
        metadata["token_count"] = len(token_lines)

        return [
            EnumerationResult(
                id="github_hosts",
                category=self.category,
                path=str(self.tokens),
                metadata=metadata,
                findings=[],
            )
        ]


def scan_github() -> list[dict]:
    return GitHubEnumerator().scan()
