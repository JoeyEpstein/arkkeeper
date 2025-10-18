"""Docker credential enumerator."""
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Iterable

from .base import BaseEnumerator, EnumerationResult


class DockerEnumerator(BaseEnumerator):
    """Inspect ~/.docker/config.json for inline credentials."""

    category = "docker"

    def __init__(self, docker_dir: Path | None = None) -> None:
        super().__init__(docker_dir or Path.home() / ".docker")
        self.config_path = self.root / "config.json"

    def iter_results(self) -> Iterable[EnumerationResult]:
        if not self.config_path.exists():
            return []

        data = json.loads(self.config_path.read_text() or "{}")
        auths = data.get("auths", {})
        credential_stores = data.get("credsStore") or data.get("credHelpers", {})

        metadata = {
            "auth_count": len(auths),
            "has_inline_auth": bool(auths),
            "credential_stores": credential_stores,
            "registries": list(auths.keys()),
        }

        # Attempt to decode auth entries without exposing secrets
        sample_decoded: list[str] = []
        for registry, auth in auths.items():
            token = auth.get("auth")
            if not token:
                continue
            try:
                decoded = base64.b64decode(token).decode("utf-8", "ignore")
                username = decoded.split(":", 1)[0]
                sample_decoded.append(f"{registry}:{username}")
            except Exception:  # pragma: no cover - defensive
                continue
        metadata["sample_accounts"] = sample_decoded

        return [
            EnumerationResult(
                id="docker_config",
                category=self.category,
                path=str(self.config_path),
                metadata=metadata,
                findings=[],
            )
        ]


def scan_docker() -> list[dict]:
    return DockerEnumerator().scan()
