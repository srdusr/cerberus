"""
Cerberus CLI - Command Line Interface for Cerberus Password Manager.
"""
import os
import sys
import logging
from typing import Optional

import click
from rich.console import Console
from rich.logging import RichHandler

from . import CerberusCLI, print_entry_table
from ..automation.playwright_engine import PlaywrightEngine
from ..automation.selenium_engine import SeleniumEngine, SELENIUM_AVAILABLE
from ..automation.runner import RotationRunner, RotationSelector
from ..automation.sites.github import GithubFlow
from ..automation.sites.google import GoogleFlow
from ..automation.sites.microsoft import MicrosoftFlow
from ..automation.sites.twitter import TwitterFlow
from ..automation.sites.facebook import FacebookFlow
from ..automation.sites.linkedin import LinkedInFlow
from ..automation.sites.apple import AppleFlow
from ..automation.policy import generate_for_entry
from ..automation.types import AutomationStatus

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("cerberus")

# Create console for rich output
console = Console()

# Default data directory
DEFAULT_DATA_DIR = os.path.expanduser("~/.cerberus")

@click.group(invoke_without_command=True)
@click.option(
    "--data-dir",
    type=click.Path(file_okay=False, dir_okay=True, writable=True),
    default=DEFAULT_DATA_DIR,
    help="Directory to store password data",
    show_default=True
)
@click.option(
    "--debug/--no-debug",
    default=False,
    help="Enable debug output",
    show_default=True
)
@click.pass_context
def cli(ctx: click.Context, data_dir: str, debug: bool) -> None:
    """Cerberus Password Manager - Secure and user-friendly password management."""
    # Set debug logging if enabled
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled")
    
    # Create data directory if it doesn't exist
    os.makedirs(data_dir, exist_ok=True)
    
    # Store the CLI instance in the context
    ctx.obj = CerberusCLI(data_dir=data_dir, debug=debug)
    
    # If no command is provided, show help
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())

@cli.command()
@click.pass_obj
def init(cli: CerberusCLI) -> None:
    """Initialize a new password vault."""
    master_password = click.prompt(
        "Enter a master password",
        hide_input=True,
        confirmation_prompt=True
    )
    
    try:
        cli.unlock_vault(master_password)
        console.print("[green]✓[/] Vault initialized and unlocked!")
    except Exception as e:
        console.print(f"[red]✗[/] Failed to initialize vault: {e}")
        sys.exit(1)

@cli.command()
@click.option("--engine", type=click.Choice(["playwright", "selenium"]), default="playwright", show_default=True)
@click.option("--all", "all_", is_flag=True, default=False, help="Include all entries")
@click.option("--compromised", is_flag=True, default=False, help="Only compromised entries")
@click.option("--tag", default=None, help="Filter by tag")
@click.option("--domain", default=None, help="Filter by domain")
@click.pass_obj
def reliability_report(
    cli: CerberusCLI,
    engine: str,
    all_: bool,
    compromised: bool,
    tag: Optional[str],
    domain: Optional[str],
) -> None:
    """Run a dry-run rotate across selected entries and report SUCCESS/NEEDS_MANUAL/FAILED counts."""
    try:
        try:
            cli.ensure_initialized()
        except Exception:
            # Attempt interactive unlock
            password = click.prompt("Master password", hide_input=True)
            cli.unlock_vault(password)
        if engine == "playwright":
            eng = PlaywrightEngine()
        else:
            if not SELENIUM_AVAILABLE:
                raise click.ClickException("Selenium not installed. Install extra: pip install .[automation-selenium]")
            eng = SeleniumEngine()

        eng.start(headless=True)
        try:
            flows = [
                GithubFlow(), GoogleFlow(), MicrosoftFlow(), TwitterFlow(),
                FacebookFlow(), LinkedInFlow(), AppleFlow()
            ]
            runner = RotationRunner(eng, flows, cli.pm)  # type: ignore[arg-type]
            selector = RotationSelector(
                all=all_,
                compromised_only=compromised,
                tag=tag,
                domain=domain,
            )
            results = runner.rotate(selector, lambda e: generate_for_entry(cli.pm, e), dry_run=True)  # type: ignore[arg-type]
            counts = {AutomationStatus.SUCCESS: 0, AutomationStatus.NEEDS_MANUAL: 0, AutomationStatus.FAILED: 0}
            for r in results:
                counts[r.status] = counts.get(r.status, 0) + 1
            console.print("[bold]Reliability Report[/bold]")
            console.print(f"SUCCESS: {counts.get(AutomationStatus.SUCCESS, 0)}")
            console.print(f"NEEDS_MANUAL: {counts.get(AutomationStatus.NEEDS_MANUAL, 0)}")
            console.print(f"FAILED: {counts.get(AutomationStatus.FAILED, 0)}")
        finally:
            eng.stop()
    except Exception as e:
        console.print(f"[red]✗[/] Reliability report failed: {e}")
        if cli.debug:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)

@cli.command()
@click.option(
    "--password",
    help="Master password (prompt if not provided)",
    default=None
)
@click.pass_obj
def unlock(cli: CerberusCLI, password: Optional[str]) -> None:
    """Unlock the password vault."""
    try:
        cli.unlock_vault(password)
        console.print("[green]✓[/] Vault unlocked!")
    except Exception as e:
        console.print(f"[red]✗[/] Failed to unlock vault: {e}")
        sys.exit(1)

@cli.command()
@click.option(
    "--search",
    "-s",
    help="Filter entries by search term"
)
@click.pass_obj
def list(cli: CerberusCLI, search: Optional[str]) -> None:
    """List all password entries."""
    try:
        entries = cli.list_entries(search)
        print_entry_table(entries)
    except Exception as e:
        console.print(f"[red]✗[/] Failed to list entries: {e}")
        sys.exit(1)

@cli.command()
@click.argument("identifier")
@click.pass_obj
def show(cli: CerberusCLI, identifier: str) -> None:
    """Show details for a specific password entry."""
    try:
        entry = cli.get_entry(identifier)
        
        console.print(f"[bold]Entry:[/bold] {entry.id}")
        console.print(f"[bold]Website:[/bold] {entry.website}")
        console.print(f"[bold]Username:[/bold] {entry.username}")
        console.print(f"[bold]Password:[/bold] {'*' * 12} (use 'cerberus copy-password {entry.id}' to copy)")
        
        if entry.url:
            console.print(f"[bold]URL:[/bold] {entry.url}")
        if entry.notes:
            console.print("[bold]Notes:[/bold]")
            console.print(entry.notes)
        if entry.tags:
            console.print(f"[bold]Tags:[/bold] {', '.join(entry.tags)}")
            
        console.print(f"[dim]Created: {entry.created_at}")
        console.print(f"[dim]Updated: {entry.updated_at}")
        if entry.last_used:
            console.print(f"[dim]Last Used: {entry.last_used}")
            
    except Exception as e:
        console.print(f"[red]✗[/] Failed to get entry: {e}")
        sys.exit(1)

@cli.command()
@click.option(
    "--website",
    "-w",
    required=True,
    help="Website or service name"
)
@click.option(
    "--username",
    "-u",
    required=True,
    help="Username or email"
)
@click.option(
    "--password",
    "-p",
    help="Password (prompt if not provided)"
)
@click.option(
    "--url",
    help="Website URL"
)
@click.option(
    "--notes",
    "-n",
    help="Additional notes"
)
@click.option(
    "--tag",
    "-t",
    "tags",
    multiple=True,
    help="Tags for organization (can be used multiple times)"
)
@click.option(
    "--generate/--no-generate",
    "-g",
    default=False,
    help="Generate a strong password"
)
@click.option(
    "--length",
    "-l",
    type=int,
    default=16,
    help="Length of generated password"
)
@click.option(
    "--no-special-chars",
    is_flag=True,
    default=False,
    help="Exclude special characters from generated password"
)
@click.pass_obj
def add(
    cli: CerberusCLI,
    website: str,
    username: str,
    password: Optional[str],
    url: str,
    notes: str,
    tags: list,
    generate: bool,
    length: int,
    no_special_chars: bool
) -> None:
    """Add a new password entry."""
    try:
        entry = cli.add_entry(
            website=website,
            username=username,
            password=password,
            url=url,
            notes=notes,
            tags=list(tags) if tags else None,
            generate=generate,
            length=length,
            special_chars=not no_special_chars
        )
        
        console.print(f"[green]✓[/] Added entry for [bold]{entry.website}[/bold]")
        if generate:
            console.print(f"Generated password: [yellow]{entry.password}[/]")
            
    except Exception as e:
        console.print(f"[red]✗[/] Failed to add entry: {e}")
        sys.exit(1)

@cli.command()
@click.argument("identifier")
@click.option(
    "--website",
    "-w",
    help="Update website name"
)
@click.option(
    "--username",
    "-u",
    help="Update username"
)
@click.option(
    "--password",
    "-p",
    help="Update password (prompt if not provided)"
)
@click.option(
    "--url",
    help="Update website URL"
)
@click.option(
    "--notes",
    "-n",
    help="Update notes"
)
@click.option(
    "--tag",
    "-t",
    "tags",
    multiple=True,
    help="Update tags (use --tag=clear to remove all tags)"
)
@click.pass_obj
def edit(
    cli: CerberusCLI,
    identifier: str,
    website: str,
    username: str,
    password: str,
    url: str,
    notes: str,
    tags: list
) -> None:
    """Edit an existing password entry."""
    try:
        # Get the current entry
        entry = cli.get_entry(identifier)
        
        # Prepare updates
        updates = {}
        
        if website is not None:
            updates["website"] = website
        if username is not None:
            updates["username"] = username
        if password is not None:
            if password == "":
                password = click.prompt("New password", hide_input=True, confirmation_prompt=True)
            updates["password"] = password
        if url is not None:
            updates["url"] = url
        if notes is not None:
            updates["notes"] = notes
        if tags:
            if tags == ("clear",):
                updates["tags"] = []
            else:
                updates["tags"] = list(tags)
        
        if not updates:
            console.print("[yellow]No changes specified.[/]")
            return
            
        # Apply updates
        updated_entry = cli.update_entry(entry.id, **updates)
        console.print(f"[green]✓[/] Updated entry for [bold]{updated_entry.website}[/]")
        
    except Exception as e:
        console.print(f"[red]✗[/] Failed to update entry: {e}")
        sys.exit(1)

@cli.command()
@click.argument("identifier")
@click.option(
    "--length",
    "-l",
    type=int,
    default=32,
    help="Length of the new password"
)
@click.option(
    "--no-special-chars",
    is_flag=True,
    default=False,
    help="Exclude special characters from the new password"
)
@click.pass_obj
def rotate(
    cli: CerberusCLI,
    identifier: str,
    length: int,
    no_special_chars: bool
) -> None:
    """Generate a new password for an entry."""
    try:
        entry = cli.rotate_password(
            identifier,
            length=length,
            special_chars=not no_special_chars
        )
        
        console.print(f"[green]✓[/] Rotated password for [bold]{entry.website}[/]")
        console.print(f"New password: [yellow]{entry.password}[/]")
        
    except Exception as e:
        console.print(f"[red]✗[/] Failed to rotate password: {e}")
        sys.exit(1)

@cli.command()
@click.argument("identifier")
@click.pass_obj
def delete(cli: CerberusCLI, identifier: str) -> None:
    """Delete a password entry."""
    try:
        cli.delete_entry(identifier)
    except Exception as e:
        console.print(f"[red]✗[/] Failed to delete entry: {e}")
        sys.exit(1)

@cli.command()
@click.argument("identifier")
@click.pass_obj
def copy_username(cli: CerberusCLI, identifier: str) -> None:
    """Copy username to clipboard."""
    try:
        entry = cli.get_entry(identifier)
        
        # Use platform-specific clipboard handling
        import pyperclip
        pyperclip.copy(entry.username)
        
        console.print(f"[green]✓[/] Copied username for [bold]{entry.website}[/] to clipboard")
        
    except Exception as e:
        console.print(f"[red]✗[/] Failed to copy username: {e}")
        sys.exit(1)

@cli.command()
@click.argument("identifier")
@click.pass_obj
def copy_password(cli: CerberusCLI, identifier: str) -> None:
    """Copy password to clipboard."""
    try:
        entry = cli.get_entry(identifier)
        
        # Use platform-specific clipboard handling
        import pyperclip
        pyperclip.copy(entry.password)
        
        console.print(f"[green]✓[/] Copied password for [bold]{entry.website}[/] to clipboard")
        
        # Clear clipboard after 30 seconds
        import threading
        import time
        
        def clear_clipboard():
            time.sleep(30)
            if pyperclip.paste() == entry.password:
                pyperclip.copy("")
                console.print("[yellow]✓[/] Clipboard cleared")
        
        threading.Thread(target=clear_clipboard, daemon=True).start()
        
    except Exception as e:
        console.print(f"[red]✗[/] Failed to copy password: {e}")
        sys.exit(1)

@cli.command()
@click.argument("output_file", type=click.Path())
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json"], case_sensitive=False),
    default="json",
    help="Export format"
)
@click.pass_obj
def export(cli: CerberusCLI, output_file: str, format: str) -> None:
    """Export password entries to a file."""
    try:
        cli.export_entries(output_file, format=format)
    except Exception as e:
        console.print(f"[red]✗[/] Failed to export entries: {e}")
        sys.exit(1)

@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json"], case_sensitive=False),
    default="json",
    help="Import format"
)
@click.pass_obj
def import_entries(cli: CerberusCLI, input_file: str, format: str) -> None:
    """Import password entries from a file."""
    try:
        cli.import_entries(input_file, format=format)
    except Exception as e:
        console.print(f"[red]✗[/] Failed to import entries: {e}")
        sys.exit(1)

@cli.command()
@click.pass_obj
def tui(cli: CerberusCLI) -> None:
    """Launch the Terminal User Interface."""
    from ..tui import main as tui_main
    tui_main()

@cli.command()
@click.pass_obj
def gui(cli: CerberusCLI) -> None:
    """Launch the Graphical User Interface."""
    from ..gui import run_app
    run_app()

@cli.command()
@click.argument("identifier", required=False)
@click.option("--engine", type=click.Choice(["playwright", "selenium"]), default="playwright", show_default=True)
@click.option("--all", "all_", is_flag=True, default=False, help="Rotate all entries")
@click.option("--compromised", is_flag=True, default=False, help="Only compromised entries")
@click.option("--tag", default=None, help="Filter by tag")
@click.option("--domain", default=None, help="Filter by domain")
@click.option("--dry-run", is_flag=True, default=False, help="Do not perform changes, simulate only")
@click.option("--user-data-dir", type=str, default=None, help="Browser user data dir for persistent sessions")
@click.option("--no-headless", is_flag=True, default=False, help="Run browser with a visible window")
@click.pass_obj
def web_rotate(
    cli: CerberusCLI,
    identifier: Optional[str],
    engine: str,
    all_: bool,
    compromised: bool,
    tag: Optional[str],
    domain: Optional[str],
    dry_run: bool,
    user_data_dir: Optional[str],
    no_headless: bool,
) -> None:
    """Rotate password(s) on websites via web automation with dynamic discovery.

    If IDENTIFIER is provided, attempts to rotate only that entry (by id or website).
    Otherwise uses filters (--all/--tag/--domain/--compromised).
    """
    try:
        cli.ensure_initialized()
        # Create automation engine
        if engine == "playwright":
            eng = PlaywrightEngine()
        else:
            if not SELENIUM_AVAILABLE:
                raise click.ClickException("Selenium not installed. Install extra: pip install .[automation-selenium]")
            eng = SeleniumEngine()

        eng.start(headless=not no_headless, user_data_dir=user_data_dir)
        try:
            flows = [
                GithubFlow(), GoogleFlow(), MicrosoftFlow(), TwitterFlow(),
                FacebookFlow(), LinkedInFlow(), AppleFlow()
            ]
            runner = RotationRunner(eng, flows, cli.pm)  # type: ignore[arg-type]
            if identifier:
                # Build selector to target specific entry
                selector = RotationSelector(all=False)
                # Temporarily filter entries by overriding internals using domain/website matching
                # We'll rely on runner._filter_entries via domain filter
                # Best-effort: put identifier into domain filter
                domain = identifier
            selector = RotationSelector(
                all=all_,
                compromised_only=compromised,
                tag=tag,
                domain=domain,
            )
            results = runner.rotate(selector, lambda e: generate_for_entry(cli.pm, e), dry_run=dry_run)  # type: ignore[arg-type]
            for r in results:
                console.print(f"[bold]{r.status.value}[/]: {r.message}")
        finally:
            eng.stop()
    except Exception as e:
        console.print(f"[red]✗[/] Web rotate failed: {e}")
        if cli.debug:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)

def main() -> None:
    """Entry point for the Cerberus CLI."""
    try:
        cli()
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        if cli.obj and cli.obj.debug:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
