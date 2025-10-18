"""Git configuration enumerator."""
from __future__ import annotations

import configparser
import re
from pathlib import Path
from typing import Iterable

from .base import BaseEnumerator, EnumerationResult


class GitEnumerator(BaseEnumerator):
    """Inspect Git configuration for embedded credentials."""

    category = "git"

    def __init__(self, config_path: Path | None = None) -> None:
        super().__init__(config_path or Path.home())
        self.git_config = self.root / ".gitconfig"
        self.git_credentials = self.root / ".git-credentials"

    def iter_results(self) -> Iterable[EnumerationResult]:
        results: list[EnumerationResult] = []

        if self.git_config.exists():
            parser = configparser.RawConfigParser()
            parser.read(self.git_config)
            metadata = {
                "has_credential_helper": parser.has_option("credential", "helper"),
                "remote_urls": _extract_remote_urls(self.git_config),
            }
            findings = []
            results.append(
                EnumerationResult(
                    id="git_config",
                    category=self.category,
                    path=str(self.git_config),
                    metadata=metadata,
                    findings=findings,
                )
            )

        if self.git_credentials.exists():
            secrets = _extract_credentials(self.git_credentials)
            metadata = {
                "credential_count": len(secrets),
                "contains_password": any(secret.get("password") for secret in secrets),
            }
            findings = []
            results.append(
                EnumerationResult(
                    id="git_stored_credentials",
                    category=self.category,
                    path=str(self.git_credentials),
                    metadata=metadata,
                    findings=findings,
                )
            )

        return results


def _extract_remote_urls(config_path: Path) -> list[str]:
    remote_urls: list[str] = []
    current_name: str | None = None
    pattern = re.compile(r"^\s*url\s*=\s*(.+)$")
    for line in config_path.read_text().splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            current_name = line
        elif line and line[0] != "[" and pattern.match(line):
            match = pattern.match(line)
            if match:
                remote_urls.append(match.group(1).strip())
    return remote_urls


def _extract_credentials(credentials_path: Path) -> list[dict[str, str]]:
    secrets: list[dict[str, str]] = []
    for line in credentials_path.read_text().splitlines():
        if not line:
            continue
        if "@" in line and "//" in line:
            # crude parse of https://user:pass@host
            try:
                auth = line.split("//", 1)[1]
                userinfo, _ = auth.split("@", 1)
                if ":" in userinfo:
                    username, password = userinfo.split(":", 1)
                else:
                    username, password = userinfo, ""
                secrets.append({"username": username, "password": password})
            except ValueError:
                continue
    return secrets


def scan_git() -> list[dict]:
    return GitEnumerator().scan()
