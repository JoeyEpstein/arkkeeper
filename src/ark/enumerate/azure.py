"""Azure CLI credential enumerator."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .base import BaseEnumerator, EnumerationResult


class AzureEnumerator(BaseEnumerator):
    """Inspect ~/.azure for cached tokens."""

    category = "azure"

    def __init__(self, azure_dir: Path | None = None) -> None:
        super().__init__(azure_dir or Path.home() / ".azure")
        self.azure_dir = self.root

    def iter_results(self) -> Iterable[EnumerationResult]:
        token_cache = self.azure_dir / "accessTokens.json"
        if not token_cache.exists():
            return []

        try:
            data = json.loads(token_cache.read_text() or "[]")
        except json.JSONDecodeError:
            data = []

        metadata = {
            "token_entries": len(data),
            "has_refresh_tokens": any("refreshToken" in entry for entry in data),
        }
        return [
            EnumerationResult(
                id="azure_tokens",
                category=self.category,
                path=str(token_cache),
                metadata=metadata,
                findings=[],
            )
        ]


def scan_azure() -> list[dict]:
    return AzureEnumerator().scan()
