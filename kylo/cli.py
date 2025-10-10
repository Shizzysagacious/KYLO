import os
import json
import time
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from .auditor import init_project, audit_path, secure_target
from .readme_manager import create_readme_interactive
from .gemini_analyzer import analyze_code_security
from .secure_storage import SecureStorage
from .usage_tracker import UsageTracker
from pathlib import Path

console = Console()
import os

# Apply color preferences from environment (fall back to magenta/purple)
PRIMARY = os.getenv('KYLO_CLI_PRIMARY_COLOR', 'magenta')
ACCENT = os.getenv('KYLO_CLI_ACCENT_COLOR', 'purple')

@click.group()
def cli():
    """Kylo - AI-powered security code auditor v1.0.0"""
    pass

@cli.command()
@click.option('--path', default='.', help='Project path to initialize')
def init(path):
    """Initialize kylo in the current project"""
    # ensure .kylo directory exists
    cwd = os.path.abspath(path)
    kylo_root = Path(cwd)
    kylo_dir = kylo_root / '.kylo'
    kylo_dir.mkdir(parents=True, exist_ok=True)

    # interactive README creation if missing
    readme = kylo_root / 'README.md'
    if not readme.exists():
        create_readme_interactive(str(readme))

    init_project(path)


@cli.group()
def config():
    """Configuration commands"""
    pass


@config.command('set-api-key')
@click.argument('service')
@click.option('--key', prompt=True, hide_input=True, confirmation_prompt=True)
def set_api_key(service, key):
    """Securely store an API key for a named service (e.g., gemini)"""
    kylo_root = Path(os.getcwd())
    ss = SecureStorage(kylo_root)
    # require admin token
    if not ss.admin_exists():
        console.print('[yellow]No admin token found. You must set an admin token before storing keys.[/yellow]')
        console.print('[yellow]Run: kylo config set-admin-token[/yellow]')
        return
    token = click.prompt('Admin token', hide_input=True)
    if not ss.verify_admin_token(token):
        console.print('[red]Invalid admin token[/red]')
        return
    # always overwrite humanwhocodes.enc
    ss.store_api_key(service, key)
    console = Console()
    console.print(f"[green]Stored API key for {service} in .kylo/secure (humanwhocodes.enc)[/green]")


@config.command('list-keys')
def list_keys():
    """List services that have API keys stored (secrets not displayed)."""
    kylo_root = Path(os.getcwd())
    ss = SecureStorage(kylo_root)
    # admin required
    if not ss.admin_exists():
        console.print('[yellow]No admin token found. Listing keys requires admin.[/yellow]')
        console.print('[yellow]Run: kylo config set-admin-token[/yellow]')
        return
    token = click.prompt('Admin token', hide_input=True)
    if not ss.verify_admin_token(token):
        console.print('[red]Invalid admin token[/red]')
        return
    keys = ss.list_keys()
    console = Console()
    if not keys:
        console.print("[yellow]No stored API keys found in .kylo/secure[/yellow]")
        return
    console.print("[green]Stored API keys:[/green]")
    for k in keys:
        console.print(f" - {k}")


@config.command('remove-api-key')
@click.argument('service')
def remove_api_key(service):
    """Remove a stored API key for a service."""
    kylo_root = Path(os.getcwd())
    ss = SecureStorage(kylo_root)
    if not ss.admin_exists():
        console.print('[yellow]No admin token found. Removing keys requires admin.[/yellow]')
        console.print('[yellow]Run: kylo config set-admin-token[/yellow]')
        return
    token = click.prompt('Admin token', hide_input=True)
    if not ss.verify_admin_token(token):
        console.print('[red]Invalid admin token[/red]')
        return
    ok = ss.remove_api_key(service)
    if ok:
        console = Console()
        console.print(f"[green]Removed stored API key for {service}[/green]")
    else:
        console = Console()
        console.print(f"[red]No stored key found for {service}[/red]")


@config.command('set-admin-token')
@click.option('--token', prompt=True, hide_input=True, confirmation_prompt=True)
def set_admin_token(token):
    """Set or overwrite the admin token for this Kylo installation"""
    kylo_root = Path(os.getcwd())
    ss = SecureStorage(kylo_root)
    ss.set_admin_token(token)
    console = Console()
    console.print('[green]Admin token set and stored in .kylo/secure (encrypted). Keep it secret![/green]')


@config.command('migrate-legacy-keys')
def migrate_legacy_keys():
    """Migrate legacy api_key_<service>.enc files into humanwhocodes.enc"""
    kylo_root = Path(os.getcwd())
    ss = SecureStorage(kylo_root)
    ok = ss.migrate_legacy_api_keys()
    console = Console()
    if ok:
        console.print('[green]Migration complete. Legacy keys moved to humanwhocodes.enc[/green]')
    else:
        console.print('[yellow]No legacy keys found to migrate or migration failed.[/yellow]')


@cli.command('stats')
def stats():
    """Show usage statistics"""
    kylo_root = Path(os.getcwd())
    tracker = UsageTracker(kylo_root)
    report = tracker.get_usage_report()
    console = Console()
    # Pretty print with colors
    from rich.pretty import Pretty
    console.print(Panel(Pretty(report), title="[bold %s]Kylo Usage Report[/bold %s]" % (PRIMARY, PRIMARY)))

@cli.command()
@click.argument('target', required=False)
def audit(target=None):
    """Audit a file or directory (defaults to current directory)"""
    cwd = os.getcwd()
    target_path = target or cwd
    report = audit_path(target_path)
    click.echo(json.dumps(report, indent=2))

@cli.command()
@click.argument('target', required=True)
def secure(target):
    """Run security hardening suggestions on a target (file or folder)"""
    secure_target(target)

if __name__ == '__main__':
    cli()
