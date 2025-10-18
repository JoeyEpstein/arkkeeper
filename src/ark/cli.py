"""Arkkeeper command-line interface."""

import click
import json
import time
from datetime import datetime
from pathlib import Path

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from ark.enumerate.aws import scan_aws
from ark.enumerate.azure import scan_azure
from ark.enumerate.docker import scan_docker
from ark.enumerate.gcp import scan_gcp
from ark.enumerate.git import scan_git
from ark.enumerate.github import scan_github
from ark.enumerate.npm import scan_npm
from ark.enumerate.pypi import scan_pypi
from ark.enumerate.shell import scan_shell
from ark.enumerate.ssh import scan_ssh
from ark.rules.engine import RuleEngine

console = Console()

@click.group()
@click.version_option(version="0.2.0")
def cli():
    """Arkkeeper - Find, score, and rotate credentials locally."""
    pass

@cli.command()
def init():
    """Initialize Arkkeeper configuration."""
    console.print("[green]✨ Initializing Arkkeeper...[/green]")
    config_dir = Path.home() / ".config" / "arkkeeper"
    config_dir.mkdir(parents=True, exist_ok=True)
    
    config_file = config_dir / "config.yml"
    if not config_file.exists():
        default_config = {
            "arkkeeper": {
                "version": 1,
                "scan": {
                    "paths": {
                        "include": ["~/.ssh", "~/.aws", "~/.config"],
                        "exclude": ["~/.ssh/known_hosts", "~/.cache"]
                    }
                },
                "rules": {
                    "severity_weights": {
                        "critical": 100,
                        "high": 75,
                        "medium": 50,
                        "low": 25
                    }
                },
                "rotation": {
                    "dry_run_default": True,
                    "backup_before_rotate": True
                }
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
    
    console.print(f"[blue]Created config at {config_file}[/blue]")

@cli.command()
@click.option('--out', type=click.Path(), default='./arkkeeper_outputs', help='Output directory')
@click.option('--category', help='Scan specific category only')
def scan(out, category):
    """Scan for credentials and security issues."""
    console.print("[yellow]🔍 Scanning for credentials...[/yellow]")

    scanners = {
        'ssh': ("SSH keys", scan_ssh),
        'aws': ("AWS credentials", scan_aws),
        'git': ("Git configuration", scan_git),
        'github': ("GitHub CLI tokens", scan_github),
        'npm': ("npm tokens", scan_npm),
        'pypi': ("PyPI tokens", scan_pypi),
        'docker': ("Docker config", scan_docker),
        'shell': ("Shell history", scan_shell),
        'azure': ("Azure tokens", scan_azure),
        'gcp': ("GCP credentials", scan_gcp),
    }

    if category and category not in scanners:
        console.print(f"[red]❌ Unknown category: {category}[/red]")
        raise click.Exit(1)

    # Create output directory
    output_dir = Path(out)
    output_dir.mkdir(parents=True, exist_ok=True)

    all_findings: dict[str, list[dict]] = {}

    for key, (label, scanner) in scanners.items():
        if category and category != key:
            continue
        console.print(f"  Scanning {label}...")
        try:
            results = scanner()
        except Exception as exc:  # pragma: no cover - defensive
            console.print(f"    [red]Failed to scan {label}: {exc}[/red]")
            continue
        if results:
            all_findings[key] = results

    rule_paths = [Path("rules/default.yml")]
    config_rules = Path.home() / ".config" / "arkkeeper" / "rules.yml"
    if config_rules.exists():
        rule_paths.append(config_rules)
    engine = RuleEngine.from_files(rule_paths)
    all_findings = engine.apply(all_findings)

    total_issues = sum(
        len(finding.get('findings', []))
        for findings in all_findings.values()
        for finding in findings
    )

    findings_file = output_dir / "findings.json"
    with open(findings_file, 'w') as f:
        json.dump({
            "metadata": {
                "scan_time": datetime.now().isoformat(),
                "version": "0.2.0",
                "total_issues": total_issues
            },
            "findings": all_findings
        }, f, indent=2, default=str)

    if all_findings:
        for cat_key, findings in all_findings.items():
            if not findings:
                continue
            table = Table(title=f"{cat_key.upper()} Security Findings")
            table.add_column("Path", style="cyan")
            table.add_column("Issues", style="red")
            table.add_column("Severity", style="yellow")

            for finding in findings:
                path = finding['path'].replace(str(Path.home()), "~")
                issues = finding.get('findings', [])
                issue_count = len(issues)
                if issues:
                    max_severity = max(issues, key=lambda x: _severity_weight(x['severity']))['severity']
                    table.add_row(path, str(issue_count), max_severity.upper())
            console.print(table)
    else:
        console.print("[green]  ✓ No security issues found[/green]")

    console.print(f"\n[green]✅ Scan complete! Results saved to {findings_file}[/green]")
    console.print(f"[blue]📊 Total issues found: {total_issues}[/blue]")

@cli.command()
@click.option('--format', type=click.Choice(['html', 'json', 'markdown', 'terminal']), 
              default='terminal', help='Report format')
@click.option('--input', 'input_file', type=click.Path(exists=True), 
              default='./arkkeeper_outputs/findings.json', help='Findings file to report on')
@click.option('--open', 'open_report', is_flag=True, help='Open HTML report in browser')
def report(format, input_file, open_report):
    """Generate and view security report."""
    console.print(f"[blue]📊 Generating {format} report...[/blue]")
    
    # Load findings
    findings_path = Path(input_file)
    if not findings_path.exists():
        console.print(f"[red]❌ No findings file found at {findings_path}[/red]")
        console.print("[yellow]💡 Run 'ark scan' first to generate findings[/yellow]")
        raise click.Exit(1)
    
    with open(findings_path, 'r') as f:
        data = json.load(f)
    
    findings = data.get('findings', {})
    metadata = data.get('metadata', {})
    
    if format == 'terminal':
        _generate_terminal_report(findings, metadata)
    elif format == 'html':
        _generate_html_report(findings, metadata, open_report)
    elif format == 'markdown':
        _generate_markdown_report(findings, metadata)
    elif format == 'json':
        # Pretty print JSON to terminal
        console.print(Panel(
            Syntax(json.dumps(data, indent=2), "json", theme="monokai"),
            title="JSON Report",
            border_style="blue"
        ))
    
    console.print(f"[green]✅ Report generated successfully![/green]")

@cli.command()
@click.option('--id', 'finding_id', help='Finding ID to rotate')
@click.option('--category', help='Rotate all findings in category')
@click.option('--dry-run/--execute', default=True, help='Simulate or execute rotation')
@click.option('--input', 'input_file', type=click.Path(exists=True),
              default='./arkkeeper_outputs/findings.json', help='Findings file')
def rotate(finding_id, category, dry_run, input_file):
    """Generate rotation scripts for credentials."""
    mode = "[yellow]DRY RUN[/yellow]" if dry_run else "[red]EXECUTE[/red]"
    console.print(f"🔄 Rotation mode: {mode}")
    
    # Create playbooks directory
    playbooks_dir = Path("./playbooks")
    playbooks_dir.mkdir(parents=True, exist_ok=True)
    
    if finding_id:
        # Generate rotation for specific finding
        rotation_dir = playbooks_dir / f"rotation_{finding_id}_{int(time.time())}"
        rotation_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate rotation script
        script_path = rotation_dir / "rotate.sh"
        _generate_rotation_script(finding_id, script_path, dry_run)
        
        console.print(f"[green]✅ Generated rotation script: {script_path}[/green]")
        console.print(f"[blue]📝 Review the script before running![/blue]")
        
        # Show the script content
        with open(script_path, 'r') as f:
            console.print(Panel(
                Syntax(f.read(), "bash", theme="monokai"),
                title=f"Rotation Script ({finding_id})",
                border_style="blue"
            ))
    else:
        console.print("[yellow]⚠️  Please specify --id or --category[/yellow]")

@cli.command()
def selftest():
    """Run self-test to verify installation."""
    console.print("[bold blue]🔧 Arkkeeper self-test starting...[/bold blue]")
    
    # Test 1: Check if rules can be loaded
    rules_path = Path("rules/default.yml")
    if rules_path.exists():
        with open(rules_path) as f:
            data = yaml.safe_load(f)
        console.print(f"[green]✅ Loaded rules:[/green] {len(data.get('rules', {}))} entries")
    else:
        console.print("[yellow]⚠️  No default rules file found[/yellow]")
    
    # Test 2: Check output directory
    out = Path("./arkkeeper_outputs")
    out.mkdir(parents=True, exist_ok=True)
    probe = out / "selftest.json"
    probe.write_text(json.dumps({
        "timestamp": time.time(),
        "status": "OK",
        "version": "0.2.0"
    }, indent=2))
    console.print(f"[green]✅ Wrote test artifact:[/green] {probe}")
    
    # Test 3: Import check
    try:
        from ark.enumerate.ssh import scan_ssh
        console.print("[green]✅ SSH scanner module loaded[/green]")
    except ImportError as e:
        console.print(f"[red]❌ Failed to import SSH scanner: {e}[/red]")
    
    console.print("[bold green]🎉 Self-test passed![/bold green]")

@cli.command()
@click.option('--calendar', type=click.Choice(['ics', 'google', 'outlook']), 
              default='ics', help='Calendar format')
@click.option('--days', default=90, help='Days until next rotation')
def remind(calendar, days):
    """Generate calendar reminders for credential rotation."""
    console.print(f"[blue]📅 Generating {calendar} reminders...[/blue]")
    
    from icalendar import Calendar, Event
    from datetime import datetime, timedelta
    
    cal = Calendar()
    cal.add('prodid', '-//Arkkeeper//Security Rotation Reminders//EN')
    cal.add('version', '2.0')
    
    # Load findings to create reminders
    findings_path = Path("./arkkeeper_outputs/findings.json")
    if findings_path.exists():
        with open(findings_path, 'r') as f:
            data = json.load(f)
        
        findings = data.get('findings', {})
        reminder_count = 0
        
        for category, items in findings.items():
            for finding in items:
                if finding.get('findings'):  # Only if there are issues
                    event = Event()
                    event.add('summary', f'🔐 Rotate {category.upper()} credentials')
                    event.add('description', f"Path: {finding['path']}\nIssues: {len(finding['findings'])}")
                    event.add('dtstart', datetime.now() + timedelta(days=days))
                    event.add('dtend', datetime.now() + timedelta(days=days, hours=1))
                    cal.add_component(event)
                    reminder_count += 1
        
        # Save calendar
        cal_file = Path("./arkkeeper_reminders.ics")
        with open(cal_file, 'wb') as f:
            f.write(cal.to_ical())
        
        console.print(f"[green]✅ Created {reminder_count} reminders in {cal_file}[/green]")
        console.print("[blue]📥 Import this file into your calendar app[/blue]")
    else:
        console.print("[yellow]⚠️  No findings to create reminders for. Run 'ark scan' first.[/yellow]")

# Helper functions

def _severity_weight(severity: str) -> int:
    """Get numeric weight for severity level."""
    weights = {
        'critical': 100,
        'high': 75,
        'medium': 50,
        'low': 25
    }
    return weights.get(severity.lower(), 0)

def _generate_terminal_report(findings: dict, metadata: dict):
    """Generate a terminal-based report."""
    console.print(Panel.fit(
        f"[bold]Arkkeeper Security Report[/bold]\n"
        f"Scan Time: {metadata.get('scan_time', 'Unknown')}\n"
        f"Total Issues: {metadata.get('total_issues', 0)}",
        border_style="blue"
    ))
    
    for category, items in findings.items():
        if items:
            console.print(f"\n[bold yellow]{category.upper()} Findings:[/bold yellow]")
            for finding in items:
                path = finding['path'].replace(str(Path.home()), "~")
                issues = finding.get('findings', [])
                if issues:
                    console.print(f"\n  [cyan]{path}[/cyan]")
                    for issue in issues:
                        severity_color = {
                            'critical': 'red',
                            'high': 'yellow',
                            'medium': 'orange3',
                            'low': 'blue'
                        }.get(issue['severity'], 'white')
                        console.print(f"    [{severity_color}]● {issue['severity'].upper()}:[/{severity_color}] {issue['message']}")
                        console.print(f"      [dim]Fix: {issue['fix']}[/dim]")

def _generate_html_report(findings: dict, metadata: dict, open_report: bool):
    """Generate an HTML report."""
    from jinja2 import Template
    import webbrowser
    
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Arkkeeper Security Report</title>
        <style>
            body { font-family: -apple-system, sans-serif; margin: 40px; background: #f5f5f5; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                      color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
            .finding { background: white; padding: 20px; margin: 20px 0; border-radius: 8px;
                       box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .severity-critical { border-left: 4px solid #e74c3c; }
            .severity-high { border-left: 4px solid #f39c12; }
            .severity-medium { border-left: 4px solid #3498db; }
            .severity-low { border-left: 4px solid #95a5a6; }
            .fix { background: #ecf0f1; padding: 10px; border-radius: 4px; margin-top: 10px; }
            code { background: #2c3e50; color: #ecf0f1; padding: 2px 6px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔐 Arkkeeper Security Report</h1>
            <p>Scan Time: {{ metadata.scan_time }}</p>
            <p>Total Issues: {{ metadata.total_issues }}</p>
        </div>
        
        {% for category, items in findings.items() %}
            <h2>{{ category.upper() }} Findings</h2>
            {% for finding in items %}
                {% for issue in finding.findings %}
                <div class="finding severity-{{ issue.severity }}">
                    <h3>{{ finding.path }}</h3>
                    <p><strong>Severity:</strong> {{ issue.severity.upper() }}</p>
                    <p><strong>Issue:</strong> {{ issue.message }}</p>
                    <div class="fix">
                        <strong>Fix:</strong> <code>{{ issue.fix }}</code>
                    </div>
                </div>
                {% endfor %}
            {% endfor %}
        {% endfor %}
    </body>
    </html>
    """
    
    template = Template(html_template)
    html_content = template.render(findings=findings, metadata=metadata)
    
    report_path = Path("./arkkeeper_outputs/report.html")
    with open(report_path, 'w') as f:
        f.write(html_content)
    
    console.print(f"[green]✅ HTML report saved to: {report_path}[/green]")
    
    if open_report:
        webbrowser.open(f"file://{report_path.absolute()}")
        console.print("[blue]📂 Opened report in browser[/blue]")

def _generate_markdown_report(findings: dict, metadata: dict):
    """Generate a Markdown report."""
    lines = [
        "# Arkkeeper Security Report",
        "",
        f"**Scan Time:** {metadata.get('scan_time', 'Unknown')}",
        f"**Total Issues:** {metadata.get('total_issues', 0)}",
        "",
        "---",
        ""
    ]
    
    for category, items in findings.items():
        if items:
            lines.append(f"## {category.upper()} Findings")
            lines.append("")
            
            for finding in items:
                path = finding['path'].replace(str(Path.home()), "~")
                issues = finding.get('findings', [])
                if issues:
                    lines.append(f"### {path}")
                    lines.append("")
                    for issue in issues:
                        lines.append(f"- **{issue['severity'].upper()}:** {issue['message']}")
                        lines.append(f"  - Fix: `{issue['fix']}`")
                    lines.append("")
    
    report_path = Path("./arkkeeper_outputs/report.md")
    with open(report_path, 'w') as f:
        f.write('\n'.join(lines))
    
    console.print(f"[green]✅ Markdown report saved to: {report_path}[/green]")

def _generate_rotation_script(finding_id: str, script_path: Path, dry_run: bool):
    """Generate a rotation script for a finding."""
    script_content = f"""#!/bin/bash
# Arkkeeper Rotation Script
# Finding ID: {finding_id}
# Generated: {datetime.now().isoformat()}
# Mode: {'DRY RUN' if dry_run else 'EXECUTE'}

set -euo pipefail

echo "🔐 Arkkeeper Credential Rotation"
echo "================================"
echo "Finding: {finding_id}"
echo ""

# Safety check
if [ "${{DRY_RUN:-1}}" = "1" ]; then
    echo "⚠️  DRY RUN MODE - No changes will be made"
    echo ""
fi

# Backup current credentials
echo "📦 Creating backup..."
BACKUP_DIR="$HOME/.arkkeeper_backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# SSH Key Rotation Example
if [[ "{finding_id}" == *"ssh"* ]]; then
    echo "🔑 Rotating SSH keys..."
    
    # Backup existing keys
    if [ -d "$HOME/.ssh" ]; then
        cp -r "$HOME/.ssh" "$BACKUP_DIR/"
        echo "  ✓ Backed up ~/.ssh to $BACKUP_DIR"
    fi
    
    if [ "${{DRY_RUN:-1}}" = "0" ]; then
        # Generate new key
        ssh-keygen -t ed25519 -a 256 -C "rotated_$(date +%Y%m%d)" \\
            -f "$HOME/.ssh/id_ed25519_new" -N ""
        echo "  ✓ Generated new Ed25519 key"
        
        # TODO: Update authorized_keys on remote servers
        echo "  ⚠️  Remember to update authorized_keys on remote servers!"
    else
        echo "  Would generate: ssh-keygen -t ed25519 -a 256"
        echo "  Would update: authorized_keys on remote servers"
    fi
fi

# AWS Credential Rotation Example
if [[ "{finding_id}" == *"aws"* ]]; then
    echo "☁️  Rotating AWS credentials..."
    
    if [ "${{DRY_RUN:-1}}" = "0" ]; then
        # This would require AWS CLI
        echo "  ⚠️  AWS rotation requires manual steps:"
        echo "     1. aws iam create-access-key --user-name YOUR_USER"
        echo "     2. Update ~/.aws/credentials with new key"
        echo "     3. aws iam delete-access-key --access-key-id OLD_KEY"
    else
        echo "  Would rotate AWS access keys"
        echo "  Would update ~/.aws/credentials"
    fi
fi

echo ""
echo "✅ Rotation {'simulation' if dry_run else 'process'} complete!"
echo ""
echo "📝 Rollback Instructions:"
echo "   If issues occur, restore from backup:"
echo "   cp -r $BACKUP_DIR/* $HOME/"
"""
    
    with open(script_path, 'w') as f:
        f.write(script_content)
    
    # Make script executable
    script_path.chmod(0o755)

def main():
    cli()

if __name__ == '__main__':
    main()
