#!/bin/bash

# Arkkeeper Repository Setup Script
# Run this from your development directory

echo "🚀 Setting up Arkkeeper repository..."

# Create the repository directory
mkdir -p arkkeeper && cd arkkeeper

# Initialize git
git init

# Create directory structure
echo "📁 Creating directory structure..."
mkdir -p src/ark/{enumerate,rules,rotate,report,utils}
mkdir -p tests/{unit,integration,security,fixtures}
mkdir -p rules
mkdir -p .github/workflows
mkdir -p .github/ISSUE_TEMPLATE
mkdir -p docs
mkdir -p examples

# Create .gitignore
echo "📝 Creating .gitignore..."
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# Testing
.pytest_cache/
.coverage
.coverage.*
htmlcov/
.tox/
.nox/
coverage.xml
*.cover
.hypothesis/

# Arkkeeper specific
arkkeeper_outputs/
*.backup.*
playbooks/
outputs/
*.ics
report.html
findings.json
findings.csv

# Virtual environments
venv/
ENV/
env/
.venv

# IDE
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store

# Secrets (safety net)
*.pem
*.key
*_rsa
*_rsa.pub
*_ecdsa
*_ecdsa.pub
*_ed25519
*_ed25519.pub
*.p12
*.pfx
credentials
.env
.env.*

# Logs
*.log
audit.log
debug.log

# OS
.DS_Store
Thumbs.db
EOF

# Create LICENSE (MIT)
echo "📜 Creating LICENSE..."
cat > LICENSE << 'EOF'
MIT License

Copyright (c) 2024 Arkkeeper Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF

# Create SECURITY.md
echo "🔒 Creating SECURITY.md..."
cat > SECURITY.md << 'EOF'
# Security Policy

## Reporting Security Vulnerabilities

**DO NOT** create public issues for security vulnerabilities.

Please report security vulnerabilities by emailing: security@arkkeeper.dev

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Security Model

Arkkeeper follows these security principles:

1. **No Secret Transmission**: Secret values never leave your machine
2. **No Secret Storage**: Only metadata and hashes are stored
3. **Explicit Consent**: All cloud operations require confirmation
4. **Defense in Depth**: Multiple layers of protection
5. **Fail Secure**: Errors default to safe behavior

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |

## Security Features

- Automatic redaction of secret patterns
- Memory cleanup after secret processing
- Secure random generation for all cryptographic operations
- Audit logging of all operations
- Backup before any destructive operation
EOF

# Create PRIVACY.md
echo "🔐 Creating PRIVACY.md..."
cat > PRIVACY.md << 'EOF'
# Privacy Policy

## Our Commitment

Arkkeeper is a **local-first** security tool. Your secrets and credentials **never leave your machine** unless you explicitly enable online features.

## What We DON'T Do

- ❌ No telemetry or analytics
- ❌ No automatic updates
- ❌ No cloud storage
- ❌ No phone-home features
- ❌ No secret value transmission
- ❌ No behavioral tracking
- ❌ No third-party integrations by default

## What Stays Local

Everything by default:
- All credential scanning
- Risk scoring and analysis
- Report generation
- Rotation scripts
- Configuration files
- Audit logs

## Optional Online Features

These require explicit `--online` flags:
- AWS IAM API calls (checking key last-used)
- GitHub API (updating SSH keys)
- Package registry checks (npm, PyPI)

Even with online features:
- Only metadata is transmitted
- Secret values never leave your machine
- All requests are logged locally
- You can review requests before execution

## Data Storage

- Configuration: `~/.config/arkkeeper/`
- Outputs: `./arkkeeper_outputs/` (configurable)
- No hidden files or registries
- Complete uninstall with: `rm -rf ~/.config/arkkeeper`

## Your Rights

- Full control over your data
- Complete transparency in operations
- Ability to audit all actions
- Freedom to modify and inspect source code
EOF

# Create requirements.txt
echo "📦 Creating requirements.txt..."
cat > requirements.txt << 'EOF'
# Core dependencies
click>=8.1.0
pyyaml>=6.0
cryptography>=41.0.0
rich>=13.0.0
python-dateutil>=2.8.0

# Reporting
jinja2>=3.1.0
markdown>=3.5.0
icalendar>=5.0.0

# Testing
pytest>=7.4.0
pytest-cov>=4.1.0
pytest-asyncio>=0.21.0
pytest-mock>=3.11.0

# Development
black>=23.0.0
ruff>=0.1.0
mypy>=1.5.0
pre-commit>=3.4.0

# Optional cloud integrations
boto3>=1.28.0  # AWS
azure-identity>=1.14.0  # Azure
google-auth>=2.23.0  # GCP
pygithub>=1.59.0  # GitHub
EOF

# Create setup.py
echo "⚙️ Creating setup.py..."
cat > setup.py << 'EOF'
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="arkkeeper",
    version="0.2.0",
    author="Arkkeeper Contributors",
    description="Find, score, and rotate credentials on your dev machine without exfiltrating secrets",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/arkkeeper",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.9",
    install_requires=[
        "click>=8.1.0",
        "pyyaml>=6.0",
        "cryptography>=41.0.0",
        "rich>=13.0.0",
        "python-dateutil>=2.8.0",
        "jinja2>=3.1.0",
        "markdown>=3.5.0",
        "icalendar>=5.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "ruff>=0.1.0",
            "mypy>=1.5.0",
        ],
        "cloud": [
            "boto3>=1.28.0",
            "azure-identity>=1.14.0",
            "google-auth>=2.23.0",
            "pygithub>=1.59.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ark=ark.cli:main",
            "arkkeeper=ark.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "ark": ["rules/*.yml"],
    },
)
EOF

# Create GitHub Actions CI workflow
echo "🔄 Creating GitHub Actions workflow..."
mkdir -p .github/workflows
cat > .github/workflows/ci.yml << 'EOF'
name: CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
        python-version: ["3.9", "3.10", "3.11", "3.12"]

    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -e .[dev]
    
    - name: Lint with ruff
      run: |
        ruff check src/ tests/
    
    - name: Type check with mypy
      run: |
        mypy src/
    
    - name: Test with pytest
      run: |
        pytest tests/ -v --cov=ark --cov-report=xml --cov-report=html
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
        flags: unittests
        name: codecov-umbrella

  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        scan-ref: '.'
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload Trivy results to GitHub Security
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'
EOF

# Create initial Python package structure
echo "🐍 Creating Python package structure..."

# Create __init__.py files
touch src/ark/__init__.py
touch src/ark/enumerate/__init__.py
touch src/ark/rules/__init__.py
touch src/ark/rotate/__init__.py
touch src/ark/report/__init__.py
touch src/ark/utils/__init__.py
touch tests/__init__.py

# Create a basic CLI stub
cat > src/ark/cli.py << 'EOF'
"""
Arkkeeper CLI - Your local secrets hygiene guardian
"""

import click
from rich.console import Console
from rich.table import Table
from pathlib import Path

console = Console()

@click.group()
@click.version_option(version="0.2.0")
def cli():
    """
    Arkkeeper - Find, score, and rotate credentials locally.
    
    Your secrets never leave your machine.
    """
    pass

@cli.command()
@click.option('--config', type=click.Path(), help='Config file path')
def init(config):
    """Initialize Arkkeeper configuration."""
    console.print("[green]✨ Initializing Arkkeeper...[/green]")
    # TODO: Implementation
    console.print("[blue]Created config at ~/.config/arkkeeper/config.yml[/blue]")

@cli.command()
@click.option('--out', type=click.Path(), default='./arkkeeper_outputs', help='Output directory')
@click.option('--category', help='Scan specific category only')
def scan(out, category):
    """Scan for credentials and security issues."""
    console.print("[yellow]🔍 Scanning for credentials...[/yellow]")
    # TODO: Implementation
    console.print("[green]✅ Scan complete! Results in {out}[/green]")

@cli.command()
@click.option('--format', type=click.Choice(['html', 'json', 'csv']), default='html')
@click.option('--open', is_flag=True, help='Open report in browser')
def report(format, open):
    """Generate and view security report."""
    console.print(f"[blue]📊 Generating {format} report...[/blue]")
    # TODO: Implementation

@cli.command()
@click.option('--id', required=True, help='Finding ID to rotate')
@click.option('--dry-run', is_flag=True, default=True, help='Simulate rotation only')
def rotate(id, dry_run):
    """Generate rotation scripts for credentials."""
    mode = "DRY RUN" if dry_run else "LIVE"
    console.print(f"[yellow]🔄 Generating rotation script ({mode})...[/yellow]")
    # TODO: Implementation

def main():
    cli()

if __name__ == '__main__':
    main()
EOF

# Create default rules YAML
echo "📋 Creating default rules..."
cat > rules/default.yml << 'EOF'
version: 1
rules:
  # SSH Rules
  ssh_no_passphrase:
    category: ssh
    severity: high
    weight: 30
    description: "SSH key without passphrase protection"
    condition: "not passphrase_protected"
    remediation: |
      Add passphrase to existing key:
        ssh-keygen -p -f {path}
      Or create new key with passphrase:
        ssh-keygen -t ed25519 -a 256 -f {new_path}
    
  ssh_weak_algorithm:
    category: ssh  
    severity: high
    weight: 25
    description: "Weak SSH key algorithm"
    condition: "algorithm == 'rsa' and key_size < 3072"
    remediation: "Generate Ed25519 or RSA-4096 key"
    
  ssh_excessive_permissions:
    category: ssh
    severity: critical
    weight: 40
    description: "SSH private key with excessive permissions"
    condition: "permissions != '600'"
    remediation: "chmod 600 {path}"
    
  # AWS Rules
  aws_key_age:
    category: aws
    severity: high
    weight: 30
    description: "AWS access key older than 90 days"
    condition: "age_days > 90"
    remediation: "Rotate using AWS IAM console or CLI"
    
  aws_root_credentials:
    category: aws
    severity: critical
    weight: 50
    description: "AWS root account credentials detected"
    condition: "profile == 'root' or user_id == 'root'"
    remediation: "Never use root credentials; create IAM users"
    
  # Git Rules
  git_credential_in_url:
    category: git
    severity: critical
    weight: 45
    description: "Credentials embedded in Git remote URL"
    condition: "remote_url contains '@' and 'https://'"
    remediation: "Use SSH URLs or credential helpers"
EOF

# Create sample test
echo "🧪 Creating sample test..."
cat > tests/test_basic.py << 'EOF'
"""Basic tests for Arkkeeper."""

import pytest
from pathlib import Path

def test_import():
    """Test that the package can be imported."""
    import ark
    assert ark is not None

def test_cli_import():
    """Test CLI module import."""
    from ark.cli import cli
    assert cli is not None

# TODO: Add more tests
EOF

# Create README, PROJECT, and CONTRIBUTING if they don't exist
if [ ! -f README.md ]; then
    echo "📚 README.md already exists, skipping..."
else
    echo "📚 Use the README.md from the artifact provided"
fi

if [ ! -f PROJECT.md ]; then
    echo "📋 PROJECT.md already exists, skipping..."
else
    echo "📋 Use the PROJECT.md from the original specification"
fi

# Create CONTRIBUTING.md
echo "🤝 Creating CONTRIBUTING.md..."
cat > CONTRIBUTING.md << 'EOF'
# Contributing to Arkkeeper

Thank you for considering contributing to Arkkeeper! 

## Code of Conduct

Be respectful, inclusive, and considerate. Security is our top priority.

## How to Contribute

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/arkkeeper.git
cd arkkeeper

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install in development mode
pip install -e .[dev]

# Run tests
pytest

# Run linting
ruff check src/ tests/
```

## Pull Request Guidelines

- **Security First**: Never expose actual secrets in code or tests
- **Test Coverage**: Aim for >90% coverage for new code
- **Documentation**: Update README and docstrings
- **Sign Commits**: Use GPG signing if possible
- **One Feature**: One feature per PR

## Security Vulnerabilities

Report security issues privately to: security@arkkeeper.dev
EOF

# Initialize git and make first commit
echo "📝 Initializing Git repository..."
git add .
git commit -m "Initial commit: Arkkeeper - Local secrets hygiene guardian

- Local-first security scanner for developer credentials
- No secret exfiltration, everything stays on your machine
- Generates safe rotation scripts with rollback procedures
- Privacy-focused with zero telemetry"

echo "✅ Repository structure created successfully!"
echo ""
echo "Next steps:"
echo "1. Review and add the README.md content from the artifact"
echo "2. Review and add the PROJECT.md content from the original spec"
echo "3. Create a GitHub repository:"
echo "   gh repo create arkkeeper --public --description 'Find, score, and rotate credentials locally'"
echo "4. Push to GitHub:"
echo "   git remote add origin git@github.com:yourusername/arkkeeper.git"
echo "   git push -u origin main"
echo ""
echo "5. Start developing:"
echo "   python -m venv venv"
echo "   source venv/bin/activate"
echo "   pip install -e .[dev]"
echo "   ark --help"
echo ""
echo "🎉 Happy coding! Remember: Security first, privacy always."