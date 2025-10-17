import click

@click.group()
def cli():
    """Arkkeeper - Find, score, and rotate credentials locally."""
    pass

@cli.command()
def init():
    """Initialize Arkkeeper configuration."""
    click.echo("✨ Initializing Arkkeeper...")

@cli.command()
def scan():
    """Scan for credentials and security issues."""
    click.echo("🔍 Scanning for credentials...")

def main():
    cli()

if __name__ == '__main__':
    main()
