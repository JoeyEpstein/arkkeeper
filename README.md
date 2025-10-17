```     _         _    _                           
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

> **Your local secrets hygiene guardian** — Find, score, and rotate credentials on your dev machine without ever exfiltrating secret material.

Arkkeeper inventories credentials on your local machine, calculates risk scores based on configurable rules, and generates safe rotation playbooks with optional calendar reminders. Everything stays local by default — no telemetry, no cloud dependencies, no secret values ever logged or transmitted.

## 🎯 Why Arkkeeper?

Every developer's machine becomes an "Ark" over time — SSH keys from 2019, AWS credentials that "just work," npm tokens with no expiration, and that one Docker config with base64 auth you meant to fix. Arkkeeper helps you:

- **Inventory** all credentials and secrets on your machine
- **Score** risk based on age, encryption, permissions, and best practices
- **Generate** safe, tested rotation scripts with rollback procedures
- **Schedule** rotation reminders that integrate with your calendar
- **Learn** security best practices through detailed remediation guides

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
ark report --open

# Generate rotation scripts for high-risk findings
ark rotate --severity high --dry-run
```

## 📊 What Gets Scanned

Arkkeeper inspects common credential locations with zero network calls by default:

| Category | Locations | Risk Signals |
|----------|-----------|--------------|
| **SSH** | `~/.ssh/*` | Unencrypted keys, weak algorithms (RSA <3072), excessive permissions, age >365d |
| **AWS** | `~/.aws/credentials`<br>`~/.aws/config` | Key age >90d, missing MFA, wildcard regions, plaintext storage |
| **Git** | `.git/config`<br>`~/.gitconfig` | Embedded credentials in URLs, plaintext credential helpers |
| **GitHub/GitLab** | `~/.config/gh/`<br>`~/.git-credentials` | PAT presence, token age, missing expiration |
| **Azure** | `~/.azure/` | Cached tokens, service principal secrets, missing federated auth |
| **GCP** | `~/.config/gcloud/` | Service account JSON keys, missing ADC configuration |
| **npm/PyPI** | `~/.npmrc`<br>`~/.pypirc` | Plaintext tokens, missing scopes, no expiration |
| **Docker** | `~/.docker/config.json` | Base64 inline auth, missing credential store |
| **Shell** | `.bashrc/.zshrc`<br>`.bash_history` | Exported secrets, command history patterns |

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
│   Reports   │◀────│ Rule Engine  │◀────│    Score    │
│ (HTML/JSON) │     │  (YAML rules)│     │  (0-100)    │
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
2. **Local-Only Default**: No network calls without explicit `--online` flags
3. **Dry-Run First**: All rotation scripts default to simulation mode
4. **Backup Everything**: Automatic backups before any destructive operation
5. **Explicit Consent**: Cloud operations require interactive confirmation
6. **Memory Safety**: Secrets are never held in memory longer than necessary
7. **Audit Trail**: All operations logged to `~/.config/arkkeeper/audit.log`

## 📋 Rule Engine

Rules are defined in YAML with explainable reasoning and remediation steps:

```yaml
# rules/default.yml
rules:
  ssh_no_passphrase:
    category: ssh
    severity: high
    weight: 30
    condition: |
      key_type in ['rsa', 'ecdsa', 'ed25519'] AND 
      passphrase_protected == false
    reason: "Unencrypted private keys can be stolen if machine is compromised"
    fix: |
      1. Create new key with passphrase:
         ssh-keygen -p -f {path}
      2. Add to ssh-agent for convenience:
         ssh-add --apple-use-keychain {path}  # macOS
      3. Update remote authorized_keys if needed
    references:
      - https://www.ssh.com/academy/ssh/passphrase

  aws_key_age:
    category: aws
    severity: high
    weight: 25
    condition: "age_days > 90"
    reason: "AWS recommends rotating access keys every 90 days"
    fix: |
      1. Create new access key:
         aws iam create-access-key --user-name {user}
      2. Update local credentials
      3. Test new key
      4. Deactivate old key:
         aws iam update-access-key --access-key-id {old_key} --status Inactive
      5. After validation, delete old key
```

## 🔄 Rotation Playbooks

Arkkeeper generates safe, tested rotation scripts for each finding:

```bash
# Example: playbooks/ssh-key-rotation-2024-01-15/rotate.sh
#!/bin/bash
set -euo pipefail

# Arkkeeper SSH Key Rotation Script
# Generated: 2024-01-15 10:30:00
# Finding ID: ssh_weak_key_001
# Risk Score: 85/100

# Safety checks
echo "🔍 Pre-rotation checks..."
if [ ! -f ~/.ssh/id_rsa ]; then
    echo "❌ Original key not found"
    exit 1
fi

# Backup
echo "💾 Creating backup..."
cp -r ~/.ssh ~/.ssh.backup.$(date +%Y%m%d_%H%M%S)

# Generate new key
echo "🔑 Generating new Ed25519 key..."
ssh-keygen -t ed25519 -a 256 -C "rotated_$(date +%Y%m%d)" \
    -f ~/.ssh/id_ed25519_new

# Test new key (dry-run by default)
if [ "${DRY_RUN:-1}" = "1" ]; then
    echo "✅ DRY RUN: Would update authorized_keys on:"
    grep -h "^Host " ~/.ssh/config 2>/dev/null | awk '{print $2}'
else
    echo "🚀 Updating remote servers..."
    # Actual rotation logic here
fi

# Rollback instructions
cat << EOF > rollback.md
# Rollback Instructions
If issues occur, restore from backup:
\`\`\`bash
rm -rf ~/.ssh
mv ~/.ssh.backup.* ~/.ssh
\`\`\`
EOF

echo "✨ Rotation complete! Review rollback.md for emergency procedures."
```

## 🎨 Output Formats

### HTML Report
Interactive dashboard with risk heatmap, sortable findings, and remediation guides:

```html
<!-- report.html structure -->
- Executive Summary (risk score, critical findings)
- Risk Heatmap (visual representation by category)
- Detailed Findings Table (sortable, filterable)
- Remediation Timeline (priority-based)
- Best Practices Checklist
```

### JSON Schema
```json
{
  "scan_metadata": {
    "timestamp": "2024-01-15T10:30:00Z",
    "version": "0.2.0",
    "hostname": "dev-laptop",
    "total_findings": 42,
    "risk_score": 73
  },
  "findings": [
    {
      "id": "ssh_weak_key_001",
      "category": "ssh",
      "path": "~/.ssh/id_rsa",
      "severity": "high",
      "score": 85,
      "rules_matched": ["ssh_weak_algorithm", "ssh_key_age"],
      "metadata": {
        "algorithm": "rsa-2048",
        "age_days": 730,
        "passphrase_protected": false,
        "permissions": "0644",
        "fingerprint": "SHA256:..."
      },
      "remediation": {
        "effort": "low",
        "impact": "medium",
        "playbook": "playbooks/ssh_weak_key_001/"
      }
    }
  ]
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
    
    parallel_workers: 4
    timeout_seconds: 300
  
  rules:
    sources:
      - rules/default.yml
      - rules/custom.yml
    
    severity_weights:
      critical: 100
      high: 75
      medium: 50
      low: 25
  
  rotation:
    dry_run_default: true
    backup_before_rotate: true
    calendar_reminders:
      ssh: 365  # days
      aws: 90
      tokens: 180
  
  privacy:
    redact_patterns:
      - 'AKIA[0-9A-Z]{16}'  # AWS keys
      - 'ghp_[a-zA-Z0-9]{36}'  # GitHub PATs
    never_log_paths:
      - ~/.gnupg
      - ~/.password-store
  
  output:
    formats: [json, html, csv]
    directory: ./arkkeeper_outputs
    compress_old_reports: true
```

## 🧪 Testing

```bash
# Run full test suite
pytest tests/ -v --cov=ark --cov-report=html

# Test with fixtures (no real secrets)
pytest tests/test_ssh.py::test_weak_key_detection

# Integration test with mock home directory
pytest tests/integration/test_full_scan.py --fixtures=tests/fixtures/fake_home

# Security regression tests
pytest tests/security/test_no_secret_leakage.py
```

### Test Coverage Areas

- **Enumerators**: File discovery, permission checks, metadata extraction
- **Parsers**: Config file formats, credential patterns, history analysis
- **Rules Engine**: Condition evaluation, scoring logic, weight calculations
- **Rotation**: Script generation, dry-run mode, rollback procedures
- **Privacy**: Secret redaction, no-leak guarantees, memory cleanup

## 📚 CLI Reference

```bash
# Core Commands
ark init [--config PATH]           # Initialize configuration
ark scan [--out DIR] [--category]  # Run security scan
ark report [--format] [--open]     # Generate/view reports
ark rotate --id FINDING [--dry]    # Generate rotation scripts
ark remind [--calendar]            # Export calendar reminders

# Analysis Commands
ark rules --list [--verbose]       # Show all rules and weights
ark explain --finding ID           # Detailed finding explanation
ark compare --baseline PATH        # Compare against previous scan

# Advanced Options
ark scan --online aws,github       # Enable cloud API checks
ark scan --no-history              # Skip shell history
ark scan --quick                   # Fast scan, fewer checks
ark rotate --all --severity high   # Bulk rotation scripts
ark export --format sarif          # SARIF for CI/CD integration

# Configuration
ark config get [KEY]               # View configuration
ark config set KEY VALUE           # Update configuration
ark config validate                # Verify configuration

# Privacy & Safety
ark clean                          # Remove all outputs/caches
ark audit --last 30d               # View audit log
ark test --fixtures                # Test with mock data
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
│   ├── workflows/
│   │   ├── ci.yml                # Tests + linting
│   │   ├── security.yml          # Security scanning
│   │   └── release.yml           # PyPI publishing
│   └── ISSUE_TEMPLATE/
├── src/ark/
│   ├── __init__.py
│   ├── cli.py                    # Click-based CLI
│   ├── config.py                 # Configuration management
│   ├── enumerate/
│   │   ├── base.py               # Abstract enumerator
│   │   ├── ssh.py                # SSH key/config scanner
│   │   ├── aws.py                # AWS credential scanner
│   │   ├── azure.py              # Azure credential scanner
│   │   ├── gcp.py                # GCP credential scanner
│   │   ├── git.py                # Git config scanner
│   │   ├── npm.py                # npm token scanner
│   │   ├── docker.py             # Docker auth scanner
│   │   └── shell.py              # Shell history scanner
│   ├── rules/
│   │   ├── engine.py             # Rule evaluation engine
│   │   ├── parser.py             # YAML rule parser
│   │   └── scoring.py            # Risk scoring logic
│   ├── rotate/
│   │   ├── base.py               # Rotation interface
│   │   ├── playbook.py           # Script generation
│   │   └── providers/            # Per-service rotation
│   ├── report/
│   │   ├── html.py               # HTML report generator
│   │   ├── json.py               # JSON output
│   │   └── calendar.py           # ICS generation
│   └── utils/
│       ├── crypto.py             # Hashing, fingerprints
│       ├── redact.py             # Secret redaction
│       └── backup.py             # Backup utilities
├── tests/
│   ├── fixtures/                  # Test data
│   ├── unit/                     # Unit tests
│   ├── integration/              # Integration tests
│   └── security/                 # Security tests
├── rules/
│   └── default.yml               # Default rule set
└── requirements.txt              # Dependencies
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
- [x] Core enumerators (SSH, AWS, Git, npm, Docker)
- [x] Basic rule engine with scoring
- [x] JSON/CSV output
- [x] HTML report generation

### v0.2 (Current)
- [ ] Rotation script generation
- [ ] Calendar reminder export (.ics)
- [ ] Extended cloud provider support
- [ ] Shell history pattern detection

### v0.3
- [ ] Rich TUI with Textual
- [ ] Local web UI (`ark serve`)
- [ ] Pluggable rule system
- [ ] GitHub Actions integration

### v1.0
- [ ] PyPI package with `pipx` support
- [ ] Signed binaries for macOS/Linux
- [ ] 95% test coverage
- [ ] Performance optimizations (<30s for typical scan)
- [ ] Enterprise features (SAML, audit compliance)

## ⚠️ Warnings & Disclaimers

### Critical Safety Notes

1. **Always backup** before rotation operations
2. **Never run** rotation scripts without reviewing them first
3. **Test in dev** before applying to production credentials
4. **Keep audit logs** for compliance and debugging
5. **Verify rollback** procedures before executing rotations

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
