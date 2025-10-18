"""npm token enumerator."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .base import BaseEnumerator, EnumerationResult


class NpmEnumerator(BaseEnumerator):
    """Inspect ~/.npmrc for plaintext tokens."""

    category = "npm"

    def __init__(self, npmrc_path: Path | None = None) -> None:
        super().__init__(npmrc_path or Path.home())
        self.npmrc = self.root / ".npmrc"

    def iter_results(self) -> Iterable[EnumerationResult]:
        if not self.npmrc.exists():
            return []

        contents = self.npmrc.read_text().splitlines()
        metadata = {
            "has_auth_token": any(line.strip().startswith("_auth=") for line in contents),
            "has_legacy_auth": any(line.strip().startswith("_authToken=") for line in contents),
            "registry_tokens": [
                line.split("=", 1)[0].strip()
                for line in contents
                if "//" in line and ("_auth" in line or "token" in line.lower())
            ],
        }
        findings: list[dict] = []
        return [
            EnumerationResult(
                id="npmrc",
                category=self.category,
                path=str(self.npmrc),
                metadata=metadata,
                findings=findings,
            )
        ]


def scan_npm() -> list[dict]:
    return NpmEnumerator().scan()
