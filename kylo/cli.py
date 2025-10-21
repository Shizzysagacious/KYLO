import os
import json
import time
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
from rich.live import Live
from rich.layout import Layout
from pathlib import Path

from .auditor import init_project, audit_path, secure_target
from .readme_manager import create_readme_interactive
from .secure_storage import SecureStorage
from .usage_tracker import UsageTracker

console = Console()

# Apply color preferences from environment
PRIMARY = os.getenv('KYLO_CLI_PRIMARY_COLOR', 'magenta')
ACCENT = os.getenv('KYLO_CLI_ACCENT_COLOR', 'purple')


def print_banner():
    """Print KYLO ASCII banner"""
    banner = f"""
[bold {PRIMARY}]
██╗  ██╗██╗   ██╗██╗      ██████╗ 
██║ ██╔╝╚██╗ ██╔╝██║     ██╔═══██╗
█████╔╝  ╚████╔╝ ██║     ██║   ██║
██╔═██╗   ╚██╔╝  ██║     ██║   ██║
██║  ██╗   ██║   ███████╗╚██████╔╝
╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ 
[/bold {PRIMARY}]
[{ACCENT}]AI-Powered Security Code Auditor v1.0.0[/{ACCENT}]
"""
    console.print(banner)


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.pass_context
def cli(ctx, verbose):
    """Kylo - AI-powered security code auditor"""
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    if verbose:
        console.print(f"[dim]Verbose mode enabled[/dim]")


@cli.command()
@click.option('--path', default='.', help='Project path to initialize')
@click.pass_context
def init(ctx, path):
    """Initialize kylo in the current project"""
    print_banner()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"[{PRIMARY}]Initializing KYLO...", total=None)
        
        cwd = os.path.abspath(path)
        kylo_root = Path(cwd)
        kylo_dir = kylo_root / '.kylo'
        kylo_dir.mkdir(parents=True, exist_ok=True)
        
        progress.update(task, description=f"[{PRIMARY}]Creating .kylo directory...")
        time.sleep(0.5)  # Visual feedback
        
        readme = kylo_root / 'README.md'
        if not readme.exists():
            progress.update(task, description=f"[{PRIMARY}]Creating README.md...")
            create_readme_interactive(str(readme))
        
        progress.update(task, description=f"[{PRIMARY}]Initializing project state...")
        init_project(path)
        
        progress.update(task, description=f"[{ACCENT}]✓ Initialization complete!")
    
    console.print(Panel(
        f"[green]✓[/green] KYLO initialized successfully!\n\n"
        f"Next steps:\n"
        f"  • Run [bold]kylo audit[/bold] to scan your code\n"
        f"  • Run [bold]kylo secure <target>[/bold] for security hardening\n"
        f"  • Run [bold]kylo stats[/bold] to view usage statistics",
        title=f"[bold {ACCENT}]Ready to Secure Your Code[/bold {ACCENT}]",
        border_style=ACCENT
    ))


@cli.group()
def config():
    """Configuration commands"""
    pass


@config.command('set-api-key')
@click.argument('service')
@click.option('--key', prompt=True, hide_input=True, confirmation_prompt=True)
@click.pass_context
def set_api_key(ctx, service, key):
    """Securely store an API key for a named service"""
    kylo_root = Path(os.getcwd())
    ss = SecureStorage(kylo_root)
    
    if not ss.admin_exists():
        console.print(Panel(
            "[yellow]⚠ No admin token found[/yellow]\n\n"
            "You must set an admin token before storing keys.\n"
            "Run: [bold]kylo config set-admin-token[/bold]",
            border_style="yellow"
        ))
        return
    
    token = click.prompt('Admin token', hide_input=True)
    if not ss.verify_admin_token(token):
        console.print("[red]✗ Invalid admin token[/red]")
        return
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"[{PRIMARY}]Encrypting and storing key...", total=None)
        ss.store_api_key(service, key)
        time.sleep(0.3)
    
    console.print(f"[green]✓ API key for {service} stored securely[/green]")


@config.command('list-keys')
@click.pass_context
def list_keys(ctx):
    """List services that have API keys stored"""
    kylo_root = Path(os.getcwd())
    ss = SecureStorage(kylo_root)
    
    if not ss.admin_exists():
        console.print("[yellow]⚠ No admin token found. Admin required.[/yellow]")
        return
    
    token = click.prompt('Admin token', hide_input=True)
    if not ss.verify_admin_token(token):
        console.print("[red]✗ Invalid admin token[/red]")
        return
    
    keys = ss.list_keys()
    
    if not keys:
        console.print("[yellow]No stored API keys found[/yellow]")
        return
    
    table = Table(title="Stored API Keys", show_header=True, header_style=f"bold {PRIMARY}")
    table.add_column("Service", style=ACCENT)
    table.add_column("Status", justify="center")
    
    for k in keys:
        table.add_row(k, "[green]✓ Active[/green]")
    
    console.print(table)


@config.command('set-admin-token')
@click.option('--token', prompt=True, hide_input=True, confirmation_prompt=True)
@click.pass_context
def set_admin_token(ctx, token):
    """Set or overwrite the admin token"""
    kylo_root = Path(os.getcwd())
    ss = SecureStorage(kylo_root)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"[{PRIMARY}]Securing admin token...", total=None)
        ss.set_admin_token(token)
        time.sleep(0.3)
    
    console.print(Panel(
        "[green]✓ Admin token set successfully[/green]\n\n"
        "[yellow]⚠ Keep this token secret![/yellow]\n"
        "You'll need it to manage API keys and sensitive operations.",
        border_style="green"
    ))


@cli.command('stats')
@click.pass_context
def stats(ctx):
    """Show usage statistics"""
    kylo_root = Path(os.getcwd())
    tracker = UsageTracker(kylo_root)
    report = tracker.get_usage_report()
    
    # Create stats table
    table = Table(title="KYLO Usage Statistics", show_header=True, header_style=f"bold {PRIMARY}")
    table.add_column("Metric", style=ACCENT)
    table.add_column("Value", justify="right")
    
    table.add_row("Days Active", f"{report['summary']['days_active']:.1f}")
    table.add_row("Total Audits", str(report['summary']['total_audits']))
    table.add_row("Security Scans", str(report['summary']['total_secure_scans']))
    table.add_row("API Calls", str(report['summary']['total_api_calls']))
    
    console.print(table)
    
    # Rate limits
    limits_table = Table(title="Rate Limits", show_header=True, header_style=f"bold {ACCENT}")
    limits_table.add_column("Operation", style=PRIMARY)
    limits_table.add_column("Limit (per hour)", justify="right")
    
    for op, limit in report['rate_limits'].items():
        limits_table.add_row(op.capitalize(), str(limit))
    
    console.print(limits_table)


@cli.command()
@click.argument('target', required=False)
@click.pass_context
def audit(ctx, target=None):
    """Audit a file or directory"""
    print_banner()
    
    cwd = os.getcwd()
    target_path = target or cwd
    
    console.print(f"\n[{PRIMARY}]Starting security audit of:[/{PRIMARY}] [bold]{target_path}[/bold]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"[{PRIMARY}]🔍 Scanning files...", total=None)
        
        # Simulated stages for better UX
        progress.update(task, description=f"[{PRIMARY}]📂 Reading project structure...")
        time.sleep(0.5)
        
        progress.update(task, description=f"[{PRIMARY}]🔍 Analyzing code patterns...")
        time.sleep(0.5)
        
        progress.update(task, description=f"[{PRIMARY}]🛡️ Running security checks...")
        report = audit_path(target_path)
        
        progress.update(task, description=f"[{ACCENT}]✓ Audit complete!")
    
    # Display results
    console.print(f"\n[bold {ACCENT}]Audit Results[/bold {ACCENT}]")
    console.print(f"Files scanned: [bold]{report['summary']['files']}[/bold]")
    console.print(f"Issues found: [bold]{report['summary']['issues']}[/bold]\n")
    
    if report['summary']['issues'] > 0:
        console.print(f"[yellow]⚠ Review .kylo/state.json for detailed findings[/yellow]")
    else:
        console.print(f"[green]✓ No security issues detected![/green]")
    
    if ctx.obj.get('verbose'):
        console.print(f"\n[dim]{json.dumps(report, indent=2)}[/dim]")


@cli.command()
@click.argument('target', required=True)
@click.pass_context
def secure(ctx, target):
    """Run security hardening on a target"""
    print_banner()
    
    console.print(f"\n[{PRIMARY}]Running security analysis on:[/{PRIMARY}] [bold]{target}[/bold]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"[{PRIMARY}]🔒 Initializing security scanner...", total=None)
        time.sleep(0.3)
        
        progress.update(task, description=f"[{PRIMARY}]🔍 Deep code analysis...")
        time.sleep(0.5)
        
        progress.update(task, description=f"[{PRIMARY}]🛡️ Checking vulnerabilities...")
        secure_target(target)
        
        progress.update(task, description=f"[{ACCENT}]✓ Security scan complete!")
    
    console.print(f"\n[green]✓ Security analysis finished[/green]")
    console.print(f"[dim]Check .kylo/state.json for recommendations[/dim]")


if __name__ == '__main__':
    cli(obj={})
