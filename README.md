# 🔐 Arkkeeper

[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-first-green)](SECURITY.md)
[![Privacy](https://img.shields.io/badge/privacy-local--first-purple)](PRIVACY.md)

> **Your local secrets hygiene guardian** — Find, score, and rotate credentials on your dev machine without ever exfiltrating secret material.

## 🚀 Quick Start
```bash
pip install arkkeeper
ark scan
ark report --open
```

## 🎯 Why Arkkeeper?

Every developer's machine becomes an "Ark" over time — SSH keys from 2019, AWS credentials that "just work," npm tokens with no expiration. Arkkeeper helps you:

- **Inventory** all credentials and secrets on your machine
- **Score** risk based on age, encryption, permissions, and best practices
- **Generate** safe, tested rotation scripts with rollback procedures
- **Schedule** rotation reminders that integrate with your calendar

## 📊 What Gets Scanned

- SSH keys and configurations
- AWS/Azure/GCP credentials
- Git credentials and tokens
- npm/PyPI tokens
- Docker auth configs
- Shell history and environment variables

Everything stays local by default — no telemetry, no cloud dependencies.

## Installation
```bash
pipx install arkkeeper  # Recommended
# or
pip install arkkeeper
```

## License

MIT License - See [LICENSE](LICENSE) file for details.
