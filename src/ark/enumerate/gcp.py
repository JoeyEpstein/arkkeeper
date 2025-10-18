"""GCP credential enumerator."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .base import BaseEnumerator, EnumerationResult


class GCPEnumerator(BaseEnumerator):
    """Inspect gcloud configuration for service account keys."""

    category = "gcp"

    def __init__(self, gcp_dir: Path | None = None) -> None:
        super().__init__(gcp_dir or Path.home() / ".config" / "gcloud")
        self.credentials_dir = self.root / "credentials.db"
        self.application_default = Path.home() / ".config" / "gcloud" / "application_default_credentials.json"

    def iter_results(self) -> Iterable[EnumerationResult]:
        results: list[EnumerationResult] = []

        if self.application_default.exists():
            try:
                data = json.loads(self.application_default.read_text() or "{}")
            except json.JSONDecodeError:
                data = {}
            metadata = {
                "has_private_key": "private_key" in data,
                "client_email": data.get("client_email", ""),
            }
            results.append(
                EnumerationResult(
                    id="gcp_adc",
                    category=self.category,
                    path=str(self.application_default),
                    metadata=metadata,
                    findings=[],
                )
            )

        if self.credentials_dir.exists():
            metadata = {
                "has_sqlite": True,
            }
            results.append(
                EnumerationResult(
                    id="gcp_credentials_db",
                    category=self.category,
                    path=str(self.credentials_dir),
                    metadata=metadata,
                    findings=[],
                )
            )

        return results


def scan_gcp() -> list[dict]:
    return GCPEnumerator().scan()
