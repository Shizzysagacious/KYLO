import os
import json
import time
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
from pathlib import Path

from .auditor import init_project, audit_path, secure_target, AuditError
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
        time.sleep(0.5)
        
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
        f"  • Run [bold]kylo audit <file.py>[/bold] to scan your code\n"
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

# ADD THIS TO cli.py after the stats() command

@cli.command('context')
@click.pass_context
def context(ctx):
    """View audit history and context"""
    from .auditor import get_context_summary
    from .utils import load_json
    
    kylo_root = Path(os.getcwd())
    kylo_dir = kylo_root / '.kylo'
    
    if not kylo_dir.exists():
        console.print(Panel(
            "[yellow]⚠ KYLO not initialized in this directory[/yellow]\n\n"
            "Please run [bold]kylo init[/bold] first.",
            border_style="yellow"
        ))
        return
    
    context_file = kylo_dir / 'context.json'
    if not context_file.exists():
        console.print("[yellow]No audit history found yet. Run [bold]kylo audit[/bold] first.[/yellow]")
        return
    
    context_data = load_json(str(context_file))
    
    # Summary Panel
    summary = get_context_summary(os.getcwd())
    if summary:
        console.print(Panel(
            f"[bold]Total Audits:[/bold] {summary['total_audits']}\n"
            f"[bold]Last Audit:[/bold] {summary['last_audit_str']}\n"
            f"[bold]Files Tracked:[/bold] {summary['files_tracked']}",
            title=f"[bold {PRIMARY}]Audit Context Summary[/bold {PRIMARY}]",
            border_style=PRIMARY
        ))
    
    # Files Table
    files_tracked = context_data.get('files_tracked', {})
    if files_tracked:
        console.print(f"\n[bold {ACCENT}]Tracked Files:[/bold {ACCENT}]")
        
        table = Table(show_header=True, header_style=f"bold {PRIMARY}")
        table.add_column("File", style=ACCENT)
        table.add_column("Audits", justify="center")
        table.add_column("Last Issues", justify="center")
        table.add_column("Last Audited", justify="right")
        
        for file_path, file_data in sorted(files_tracked.items()):
            last_audited = file_data.get('last_audited', 0)
            if last_audited:
                days_ago = (time.time() - last_audited) / 86400
                if days_ago < 1:
                    time_str = "today"
                elif days_ago < 2:
                    time_str = "yesterday"
                else:
                    time_str = f"{int(days_ago)}d ago"
            else:
                time_str = "never"
            
            last_issues = file_data.get('last_issues', 0)
            issue_color = "red" if last_issues > 0 else "green"
            
            # Shorten file path for display
            display_path = file_path if len(file_path) < 50 else "..." + file_path[-47:]
            
            table.add_row(
                display_path,
                str(file_data.get('audit_count', 0)),
                f"[{issue_color}]{last_issues}[/{issue_color}]",
                time_str
            )
        
        console.print(table)
    
    # Vulnerability History
    vuln_history = context_data.get('vulnerability_history', [])
    if vuln_history and len(vuln_history) > 1:
        console.print(f"\n[bold {ACCENT}]Recent Audit Trend:[/bold {ACCENT}]")
        
        # Show last 5 audits
        recent = vuln_history[-5:]
        for i, audit in enumerate(recent, 1):
            timestamp = audit.get('timestamp', 0)
            total_issues = audit.get('total_issues', 0)
            files_audited = audit.get('files_audited', 0)
            
            date_str = time.strftime('%Y-%m-%d %H:%M', time.localtime(timestamp))
            issue_color = "red" if total_issues > 0 else "green"
            
            console.print(
                f"  [{i}] {date_str} - "
                f"[{issue_color}]{total_issues} issues[/{issue_color}] in {files_audited} files"
            )
    
    console.print(f"\n[dim]💡 Tip: Run [bold]kylo audit .[/bold] to update your context[/dim]")    


@cli.command()
@click.argument('target', required=False)
@click.pass_context
def audit(ctx, target=None):
    """Audit a file or directory"""
    print_banner()
    
    cwd = os.getcwd()
    target_path = target or cwd
    
    # Check if .kylo directory exists
    kylo_dir = Path(cwd) / '.kylo'
    if not kylo_dir.exists():
        console.print(Panel(
            "[yellow]⚠ KYLO not initialized in this directory[/yellow]\n\n"
            "Please run [bold]kylo init[/bold] first to set up your project.",
            border_style="yellow"
        ))
        return
    
    console.print(f"\n[{PRIMARY}]Starting security audit of:[/{PRIMARY}] [bold]{target_path}[/bold]\n")
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"[{PRIMARY}]🔍 Analyzing target...", total=None)
            
            progress.update(task, description=f"[{PRIMARY}]📂 Validating files...")
            time.sleep(0.3)
            
            progress.update(task, description=f"[{PRIMARY}]🔍 Running security checks...")
            report = audit_path(target_path)
            
            # Check for errors
            if "error" in report:
                progress.update(task, description=f"[red]✗ Audit failed[/red]")
                return
            
            progress.update(task, description=f"[{ACCENT}]✓ Audit complete!")
        
        # Display results
        if report['summary']['issues'] == 0:
            console.print(Panel(
                f"[green]✓ No security issues detected![/green]\n\n"
                f"Files scanned: [bold]{report['summary']['files']}[/bold]",
                title=f"[bold green]Clean Audit[/bold green]",
                border_style="green"
            ))
        else:
            console.print(Panel(
                f"Files scanned: [bold]{report['summary']['files']}[/bold]\n"
                f"Issues found: [bold red]{report['summary']['issues']}[/bold red]\n\n"
                f"[yellow]⚠ Review .kylo/state.json for detailed findings[/yellow]",
                title=f"[bold yellow]Audit Results[/bold yellow]",
                border_style="yellow"
            ))
        
        if ctx.obj.get('verbose'):
            console.print(f"\n[dim]{json.dumps(report, indent=2)}[/dim]")
            
    except AuditError as e:
        console.print(f"\n[red]{str(e)}[/red]")
    except Exception as e:
        console.print(f"\n[red]❌ Unexpected error: {str(e)}[/red]")
        if ctx.obj.get('verbose'):
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")


@cli.command()
@click.argument('target', required=True)
@click.pass_context
def secure(ctx, target):
    """Run security hardening on a target"""
    print_banner()
    
    # Check if .kylo directory exists
    kylo_dir = Path(os.getcwd()) / '.kylo'
    if not kylo_dir.exists():
        console.print(Panel(
            "[yellow]⚠ KYLO not initialized in this directory[/yellow]\n\n"
            "Please run [bold]kylo init[/bold] first to set up your project.",
            border_style="yellow"
        ))
        return
    
    console.print(f"\n[{PRIMARY}]Running security analysis on:[/{PRIMARY}] [bold]{target}[/bold]\n")
    
    try:
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
        
    except AuditError as e:
        console.print(f"\n[red]{str(e)}[/red]")
    except Exception as e:
        console.print(f"\n[red]❌ Error during security scan: {str(e)}[/red]")


if __name__ == '__main__':
    cli(obj={})