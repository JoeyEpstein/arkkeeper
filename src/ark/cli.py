import click
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table

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
    console.print(f"[blue]Created config at {config_dir}/config.yml[/blue]")

@cli.command()
@click.option('--out', type=click.Path(), default='./arkkeeper_outputs')
def scan(out):
    """Scan for credentials and security issues."""
    console.print("[yellow]🔍 Scanning for credentials...[/yellow]")
    
    # Import here to avoid circular imports
    from ark.enumerate.ssh import scan_ssh
    
    # Create output directory
    output_dir = Path(out)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Run SSH scanner
    console.print("  Scanning SSH keys...")
    ssh_findings = scan_ssh()
    
    # Save findings
    findings_file = output_dir / "findings.json"
    with open(findings_file, 'w') as f:
        json.dump({"ssh": ssh_findings}, f, indent=2, default=str)
    
    # Display summary
    if ssh_findings:
        table = Table(title="SSH Security Findings")
        table.add_column("Path", style="cyan")
        table.add_column("Issues", style="red")
        
        for finding in ssh_findings:
            path = finding['path'].replace(str(Path.home()), "~")
            issues = len(finding.get('findings', []))
            table.add_row(path, str(issues))
        
        console.print(table)
    else:
        console.print("[green]  ✓ No SSH issues found[/green]")
    
    console.print(f"\n[green]✅ Scan complete! Results saved to {findings_file}[/green]")

def main():
    cli()

if __name__ == '__main__':
    main()
