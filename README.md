```
     _         _    _                           
    / \   _ __| | _| | _____  ___ _ __   ___ _ __ 
   / _ \ | '__| |/ / |/ / _ \/ _ \ '_ \ / _ \ '__|
  / ___ \| |  |   <|   <  __/  __/ |_) |  __/ |   
 /_/   \_\_|  |_|\_\_|\_\___|\___| .__/ \___|_|   
                                  |_|              
         Your secrets. Your control. Your peace of mind.
```

[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-first-green)](SECURITY.md)
[![Privacy](https://img.shields.io/badge/privacy-local--first-purple)](PRIVACY.md)
[![License](https://img.shields.io/badge/license-MIT-orange)](LICENSE)

> **Your local secrets hygiene guardian** — Find risky credentials on your dev machine, triage them with declarative rules, and generate local-only rotation playbooks.

Arkkeeper inventories credentials on your local machine, assigns severity levels based on YAML rules, and generates safe rotation playbooks with optional calendar reminders. Everything stays local by default — no telemetry, no cloud dependencies, no secret values ever logged or transmitted.

## 🎯 Why Arkkeeper?

Every developer's machine becomes an "Ark" over time — SSH keys from 2019, AWS credentials that "just work," npm tokens with no expiration, and that one Docker config with base64 auth you meant to fix. Arkkeeper helps you:

- **Inventory** common developer credential stores on your machine
- **Prioritize** remediation using YAML-based severity rules
- **Generate** rotation scripts with built-in dry-run and rollback guidance
- **Schedule** rotation reminders that integrate with your calendar
- **Learn** security best practices through actionable remediation text

## 🚀 Quick Start

```bash
# Install via pip
pip install arkkeeper

# Or use pipx for isolated environment (recommended)
pipx install arkkeeper

# Initialize configuration
ark init

# Run your first scan
ark scan

# View the HTML report
ark report --format html --open

# Generate a rotation script for a finding
ark rotate --id ssh_key_example --dry-run

# Export calendar reminders
ark remind --calendar ics --days 90
```

> **Tip:** From a cloned repository checkout you can run the full workflow end-to-end with `bash scripts/run_arkkeeper_demo.sh`.

## 📊 What Gets Scanned

Arkkeeper inspects common credential locations with zero network calls by default:

| Category | Locations | Risk Signals |
|----------|-----------|--------------|
| **SSH** | `~/.ssh/*` | Missing passphrases, legacy DSA keys, permissive file modes, age >365d |
| **AWS** | `~/.aws/credentials`<br>`~/.aws/config` | Key file age >90d, missing MFA metadata, default profile usage |
| **Git** | `.git/config`<br>`~/.gitconfig` | Credentials embedded in remotes, plaintext credential store |
| **GitHub CLI** | `~/.config/gh/hosts.yml` | Stored personal access tokens |
| **Azure CLI** | `~/.azure/accessTokens.json` | Cached access/refresh tokens |
| **GCP** | `~/.config/gcloud/` | Application Default Credentials with private keys |
| **npm** | `~/.npmrc` | Inline `_auth` or `_authToken` entries |
| **PyPI** | `~/.pypirc` | Plaintext passwords |
| **Docker** | `~/.docker/config.json` | Base64 inline auth entries, missing credential store |
| **Shell History** | `.bash_history`<br>`.zsh_history` | Commands matching token/password patterns |

## 🛡️ Security Architecture

### Privacy-First Design

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Local FS  │────▶│  Enumerators │────▶│   Signals   │
│  (configs,  │     │  (metadata   │     │  (age,      │
│   keys)     │     │   only)      │     │   perms)    │
└─────────────┘     └──────────────┘     └─────────────┘
                                                 │
                                                 ▼
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Reports   │◀────│ Rule Engine  │◀────│  Severity   │
│ (HTML/JSON) │     │  (YAML rules)│     │  labels     │
└─────────────┘     └──────────────┘     └─────────────┘
                            │
                            ▼
                    ┌──────────────┐
                    │  Playbooks   │
                    │ (rotation    │
                    │  scripts)    │
                    └──────────────┘
```

### Core Security Principles

1. **No Secret Values**: Only metadata (fingerprints, hashes, paths, ages) are processed
2. **Local-Only Default**: No network calls or remote uploads
3. **Dry-Run First**: All rotation scripts default to simulation mode
4. **Backup Everything**: Generated playbooks back up files before changing them
5. **Configurable Rules**: YAML files drive severity and remediation text
6. **Local Outputs**: Reports, playbooks, and reminders stay on disk until you share them

## 📋 Rule Engine

Rules are defined in YAML with explainable reasoning and remediation steps:

```yaml
# rules/default.yml
rules:
  ssh_no_passphrase:
    category: ssh
    severity: high
    weight: 30
    description: "SSH key without passphrase protection"
    condition: "not passphrase_protected"
    remediation: |
      Add a passphrase to the key:
        ssh-keygen -p -f {path}

  aws_missing_mfa:
    category: aws
    severity: high
    weight: 20
    description: "AWS profile missing MFA configuration"
    condition: "not has_mfa"
    remediation: "Configure mfa_serial in ~/.aws/config and require MFA for access"

  git_plaintext_store:
    category: git
    severity: high
    weight: 35
    description: "Git credentials stored in plaintext"
    condition: "contains_password"
    remediation: "Switch to a credential helper instead of storing passwords"
```

## 🔄 Rotation Playbooks

Arkkeeper generates safe, tested rotation scripts for each finding:

```bash
# Example: playbooks/rotation_ssh_example_1700000000/rotate.sh
#!/bin/bash
# Arkkeeper Rotation Script
# Finding ID: ssh_example
# Generated: 2024-01-15T10:30:00
# Mode: DRY RUN

set -euo pipefail

echo "🔐 Arkkeeper Credential Rotation"
echo "================================"
echo "Finding: ssh_example"
echo ""

if [ "${DRY_RUN:-1}" = "1" ]; then
    echo "⚠️  DRY RUN MODE - No changes will be made"
    echo ""
fi

echo "📦 Creating backup..."
BACKUP_DIR="$HOME/.arkkeeper_backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

if [[ "ssh_example" == *"ssh"* ]]; then
    echo "🔑 Rotating SSH keys..."
    if [ -d "$HOME/.ssh" ]; then
        cp -r "$HOME/.ssh" "$BACKUP_DIR/"
        echo "  ✓ Backed up ~/.ssh to $BACKUP_DIR"
    fi
    if [ "${DRY_RUN:-1}" = "0" ]; then
        ssh-keygen -t ed25519 -a 256 -C "rotated_$(date +%Y%m%d)" \
            -f "$HOME/.ssh/id_ed25519_new" -N ""
        echo "  ✓ Generated new Ed25519 key"
    else
        echo "  Would generate a new Ed25519 key"
        echo "  Would update authorized_keys on remote hosts"
    fi
fi

echo ""
echo "✅ Rotation simulation complete!"
echo "📝 Rollback: cp -r $BACKUP_DIR/* $HOME/"
```

## 🎨 Output Formats

### HTML Report
Static HTML with severity badges and remediation text generated from the rule engine.

### JSON Schema
```json
{
  "metadata": {
    "scan_time": "2024-01-15T10:30:00",
    "version": "0.2.0",
    "total_issues": 5
  },
  "findings": {
    "ssh": [
      {
        "id": "ssh_id_rsa",
        "category": "ssh",
        "path": "/Users/me/.ssh/id_rsa",
        "metadata": {
          "permissions": "644",
          "age_days": 730,
          "key_type": "rsa",
          "passphrase_protected": false
        },
        "findings": [
          {
            "severity": "high",
            "rule": "ssh_no_passphrase",
            "message": "SSH key without passphrase protection",
            "weight": 30,
            "fix": "ssh-keygen -p -f /Users/me/.ssh/id_rsa"
          }
        ]
      }
    ]
  }
}
```

### Calendar Integration (.ics)
```ics
BEGIN:VEVENT
SUMMARY:🔐 Rotate AWS Access Key (Arkkeeper)
DTSTART:20240415T100000Z
DESCRIPTION:AWS access key in profile 'production' is 90 days old.\n\nRun: ark rotate --id aws_key_age_002
LOCATION:~/.aws/credentials
BEGIN:VALARM
TRIGGER:-P1D
DESCRIPTION:Rotation reminder
END:VALARM
END:VEVENT
```

## ⚙️ Configuration

```yaml
# ~/.config/arkkeeper/config.yml
arkkeeper:
  version: 1
  
  scan:
    paths:
      include:
        - ~/.ssh
        - ~/.aws
        - ~/.config
      exclude:
        - ~/.ssh/known_hosts
        - ~/.cache
    
  rotation:
    dry_run_default: true
    backup_before_rotate: true

  output:
    formats: [json, html, markdown]
    directory: ./arkkeeper_outputs
    compress_old_reports: true
```

## 🧪 Testing

```bash
# Run the available unit tests
pytest tests/test_ssh.py -v
```

## 📚 CLI Reference

```bash
ark init                          # Initialize configuration directory
ark scan [--out DIR] [--category] # Run credential scan
ark report [--format] [--open]    # Generate or view reports
ark rotate --id FINDING [--dry-run/--execute] # Create rotation script
ark remind [--calendar] [--days]  # Export rotation reminders
ark selftest                      # Verify installation dependencies
```

## 🔧 Development

### Repository Structure

```
arkkeeper/
├── README.md                      # This file
├── PROJECT.md                     # Full specification
├── PRIVACY.md                     # Privacy policy and guarantees
├── SECURITY.md                    # Security model and threat analysis
├── CONTRIBUTING.md                # Contribution guidelines
├── LICENSE                        # MIT License
├── .github/
│   └── workflows/
│       └── ci.yml                # Pytest smoke in CI
├── scripts/
│   └── run_arkkeeper_demo.sh     # End-to-end demo helper
├── src/ark/
│   ├── __init__.py
│   ├── cli.py                    # Click-based CLI entry point
│   ├── enumerate/
│   │   ├── __init__.py
│   │   ├── base.py               # Enumeration scaffolding
│   │   ├── aws.py                # AWS credential scanner
│   │   ├── azure.py              # Azure token scanner
│   │   ├── docker.py             # Docker auth scanner
│   │   ├── gcp.py                # GCP credential scanner
│   │   ├── git.py                # Git config scanner
│   │   ├── github.py             # GitHub CLI scanner
│   │   ├── npm.py                # npm token scanner
│   │   ├── pypi.py               # PyPI token scanner
│   │   ├── shell.py              # Shell history scanner
│   │   └── ssh.py                # SSH key/config scanner
│   ├── report/
│   │   └── __init__.py
│   ├── rotate/
│   │   └── __init__.py
│   └── rules/
│       ├── __init__.py
│       ├── engine.py             # Rule evaluation engine
│       └── parser.py             # YAML rule parser
├── tests/
│   └── test_ssh.py               # SSH enumerator unit tests
├── rules/
│   └── default.yml               # Default rule set
└── setup.py                      # Legacy setuptools helper
```

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Key points:

1. **Security First**: Any PR that could expose secrets will be rejected
2. **Privacy Paramount**: No telemetry or phone-home features
3. **Test Coverage**: New features require tests (aim for >90% coverage)
4. **Documentation**: Update README and add examples
5. **Signed Commits**: GPG-sign your commits

## 🚦 Roadmap

### v0.1 (MVP) ✅
- [x] SSH credential enumeration
- [x] CLI scaffolding and local reports

### v0.2 (Current)
- [x] Rule-driven severity engine
- [x] Multi-service enumerators (AWS, Git, GitHub, npm, Docker, Azure, GCP, PyPI, shell)
- [x] Rotation playbook generation
- [x] Calendar reminder export (.ics)

### v0.3
- [ ] Additional rule packs and customization helpers
- [ ] Extended reporting (aggregated summaries, markdown tuning)
- [ ] CLI quality-of-life improvements

## ⚠️ Warnings & Disclaimers

### Critical Safety Notes

1. **Always backup** before rotation operations
2. **Never run** rotation scripts without reviewing them first
3. **Test in dev** before applying to production credentials
4. **Verify rollback** procedures before executing rotations

### Legal

- Arkkeeper is provided "as-is" without warranties
- Not responsible for credential loss or service disruption
- Always follow your organization's security policies
- Some features may require additional authentication

## 🤝 Support & Community

- **Issues**: [GitHub Issues](https://github.com/yourusername/arkkeeper/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/arkkeeper/discussions)
- **Security**: Report vulnerabilities via [SECURITY.md](SECURITY.md)
- **Twitter**: [@arkkeeper](https://twitter.com/arkkeeper)

## 📜 License

MIT License - See [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by [truffleHog](https://github.com/trufflesecurity/trufflehog) for secret detection patterns
- Rule engine design influenced by [Semgrep](https://semgrep.dev/)
- Calendar integration inspired by [pass-rotate](https://github.com/ddevault/pass-rotate)

---

**Remember**: Security is a journey, not a destination. Arkkeeper helps you take the first steps toward better credential hygiene, but staying secure requires ongoing vigilance and good practices.

```
     _         _    _                           
    / \   _ __| | _| | _____  ___ _ __   ___ _ __ 
   / _ \ | '__| |/ / |/ / _ \/ _ \ '_ \ / _ \ '__|
  / ___ \| |  |   <|   <  __/  __/ |_) |  __/ |   
 /_/   \_\_|  |_|\_\_|\_\___|\___| .__/ \___|_|   
                                  |_|              
         Your secrets. Your control. Your peace of mind.
```
