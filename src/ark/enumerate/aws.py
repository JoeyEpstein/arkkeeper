"""AWS credential enumerator."""
from __future__ import annotations

import configparser
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .base import BaseEnumerator, EnumerationResult


class AWSEnumerator(BaseEnumerator):
    """Inspect ~/.aws for long-lived or risky credentials."""

    category = "aws"

    def __init__(self, aws_dir: Path | None = None) -> None:
        super().__init__(aws_dir or Path.home() / ".aws")
        self.aws_dir = self.root

    def iter_results(self) -> Iterable[EnumerationResult]:
        credentials_path = self.aws_dir / "credentials"
        config_path = self.aws_dir / "config"
        if not credentials_path.exists():
            return []

        parser = configparser.RawConfigParser()
        parser.read(credentials_path)
        file_mtime = datetime.fromtimestamp(credentials_path.stat().st_mtime)
        age_days = (datetime.now() - file_mtime).days

        results: list[EnumerationResult] = []
        for section in parser.sections():
            metadata = {
                "profile": section,
                "age_days": age_days,
                "has_mfa": False,
                "access_key_id": parser.get(section, "aws_access_key_id", fallback=""),
                "is_root": section.lower() == "default",
            }

            # Determine if MFA appears enabled from config
            metadata["has_mfa"] = _profile_has_mfa(config_path, section)

            findings = []
            if metadata["access_key_id"].startswith("AKIA"):
                metadata["key_prefix"] = metadata["access_key_id"][:4]
            else:
                metadata["key_prefix"] = metadata["access_key_id"][:3]

            results.append(
                EnumerationResult(
                    id=f"aws_{section}",
                    category=self.category,
                    path=str(credentials_path),
                    metadata=metadata,
                    findings=findings,
                )
            )

        return results


def _profile_has_mfa(config_path: Path, profile: str) -> bool:
    if not config_path.exists():
        return False

    parser = configparser.RawConfigParser()
    parser.read(config_path)
    profile_key = f"profile {profile}" if profile != "default" else profile
    if not parser.has_section(profile_key):
        return False
    for option in parser.options(profile_key):
        if option.endswith("_mfa_serial") or option == "mfa_serial":
            return True
    return False


def scan_aws() -> list[dict]:
    """Convenience function matching SSH enumerator signature."""
    return AWSEnumerator().scan()
