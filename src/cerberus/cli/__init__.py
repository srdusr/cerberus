"""
Cerberus CLI - Command Line Interface for Cerberus Password Manager.
"""
from typing import Optional, List, Dict, Any
import logging
import sys
import json
from pathlib import Path
from datetime import datetime
import getpass

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..core.password_manager import PasswordManager, VaultError
from ..core.models import PasswordEntry
from ..tui import main as tui_main

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# Create console for rich output
console = Console()

class CerberusCLI:
    """Main CLI application for Cerberus Password Manager."""
    
    def __init__(self, data_dir: Optional[str] = None, debug: bool = False):
        """Initialize the CLI."""
        self.data_dir = data_dir
        self.debug = debug
        self.pm: Optional[PasswordManager] = None
        
        if debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logger.debug("Debug mode enabled")
    
    def ensure_initialized(self) -> None:
        """Ensure the password manager is initialized."""
        if not self.pm:
            raise click.UsageError("Vault is not unlocked. Use 'cerberus unlock' first.")
    
    def unlock_vault(self, master_password: Optional[str] = None) -> None:
        """Unlock the password vault."""
        try:
            if not master_password:
                master_password = getpass.getpass("Master password: ")
                
            with self._progress_spinner("Unlocking vault..."):
                self.pm = PasswordManager(data_dir=self.data_dir, master_password=master_password)
                
            console.print("[green]✓[/] Vault unlocked successfully!")
            
        except VaultError as e:
            raise click.ClickException(f"Failed to unlock vault: {e}")
        except Exception as e:
            if self.debug:
                logger.exception("Error unlocking vault")
            raise click.ClickException(f"An error occurred: {e}")
    
    def _progress_spinner(self, description: str):
        """Create a progress spinner context manager."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        )
    
    def list_entries(self, search: Optional[str] = None) -> List[PasswordEntry]:
        """List password entries, optionally filtered by search term."""
        self.ensure_initialized()
        
        try:
            entries = self.pm.get_entries()
            
            if search:
                search = search.lower()
                entries = [
                    e for e in entries 
                    if search in e.website.lower() or 
                       search in (e.username or "").lower() or
                       search in (e.notes or "").lower() or
                       any(search in tag.lower() for tag in (e.tags or []))
                ]
                
            return entries
            
        except Exception as e:
            if self.debug:
                logger.exception("Error listing entries")
            raise click.ClickException(f"Failed to list entries: {e}")
    
    def get_entry(self, identifier: str) -> PasswordEntry:
        """Get a specific password entry by ID or website."""
        self.ensure_initialized()
        
        try:
            # Try to get by ID first
            try:
                return self.pm.get_entry(identifier)
            except (ValueError, KeyError):
                # If not found by ID, try by website
                entries = [e for e in self.pm.get_entries() if e.website.lower() == identifier.lower()]
                if not entries:
                    raise ValueError(f"No entry found with ID or website: {identifier}")
                if len(entries) > 1:
                    raise ValueError(f"Multiple entries found for website: {identifier}. Please use the entry ID instead.")
                return entries[0]
                
        except Exception as e:
            if self.debug:
                logger.exception(f"Error getting entry: {identifier}")
            raise click.ClickException(str(e))
    
    def add_entry(
        self, 
        website: str, 
        username: str, 
        password: Optional[str] = None,
        url: str = "",
        notes: str = "",
        tags: Optional[List[str]] = None,
        generate: bool = False,
        length: int = 16,
        special_chars: bool = True
    ) -> PasswordEntry:
        """Add a new password entry."""
        self.ensure_initialized()
        
        try:
            if generate:
                with self._progress_spinner("Generating strong password..."):
                    password = self.pm.generate_password_easy(length=length, special=special_chars)
            elif not password:
                password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
            
            entry = PasswordEntry(
                id=self.pm.generate_id(),
                website=website,
                username=username,
                password=password,
                url=url,
                notes=notes,
                tags=tags or [],
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            
            with self._progress_spinner("Saving entry..."):
                self.pm.add_entry(entry)
                
            return entry
            
        except Exception as e:
            if self.debug:
                logger.exception("Error adding entry")
            raise click.ClickException(f"Failed to add entry: {e}")
    
    def update_entry(self, entry_id: str, **updates) -> PasswordEntry:
        """Update an existing password entry."""
        self.ensure_initialized()
        
        try:
            entry = self.get_entry(entry_id)
            
            # Apply updates
            for key, value in updates.items():
                if value is not None and hasattr(entry, key):
                    setattr(entry, key, value)
            
            entry.updated_at = datetime.utcnow()
            
            with self._progress_spinner("Updating entry..."):
                self.pm.update_entry(entry)
                
            return entry
            
        except Exception as e:
            if self.debug:
                logger.exception(f"Error updating entry: {entry_id}")
            raise click.ClickException(f"Failed to update entry: {e}")
    
    def delete_entry(self, entry_id: str) -> None:
        """Delete a password entry."""
        self.ensure_initialized()
        
        try:
            entry = self.get_entry(entry_id)
            
            if click.confirm(f"Are you sure you want to delete the entry for {entry.website}?"):
                with self._progress_spinner("Deleting entry..."):
                    self.pm.delete_entry(entry.id)
                    
                console.print(f"[green]✓[/] Deleted entry for {entry.website}")
                
        except Exception as e:
            if self.debug:
                logger.exception(f"Error deleting entry: {entry_id}")
            raise click.ClickException(f"Failed to delete entry: {e}")
    
    def rotate_password(
        self, 
        entry_id: str, 
        length: int = 32,
        special_chars: bool = True
    ) -> PasswordEntry:
        """Generate a new password for an entry."""
        self.ensure_initialized()
        
        try:
            entry = self.get_entry(entry_id)
            
            with self._progress_spinner("Generating new password..."):
                new_password = self.pm.generate_password_easy(length=length, special=special_chars)
                
            entry.password = new_password
            entry.updated_at = datetime.utcnow()
            
            with self._progress_spinner("Saving updated entry..."):
                self.pm.update_entry(entry)
                
            return entry
            
        except Exception as e:
            if self.debug:
                logger.exception(f"Error rotating password for entry: {entry_id}")
            raise click.ClickException(f"Failed to rotate password: {e}")
    
    def export_entries(self, output_file: str, format: str = "json") -> None:
        """Export password entries to a file."""
        self.ensure_initialized()
        
        try:
            entries = self.pm.get_entries()
            output_path = Path(output_file).expanduser().resolve()
            
            with self._progress_spinner(f"Exporting entries to {output_path}..."):
                if format.lower() == "json":
                    data = [e.to_dict() for e in entries]
                    output_path.write_text(json.dumps(data, indent=2, default=str))
                else:
                    raise ValueError(f"Unsupported export format: {format}")
                    
            console.print(f"[green]✓[/] Exported {len(entries)} entries to {output_path}")
            
        except Exception as e:
            if self.debug:
                logger.exception("Error exporting entries")
            raise click.ClickException(f"Failed to export entries: {e}")
    
    def import_entries(self, input_file: str, format: str = "json") -> None:
        """Import password entries from a file."""
        self.ensure_initialized()
        
        try:
            input_path = Path(input_file).expanduser().resolve()
            
            if not input_path.exists():
                raise FileNotFoundError(f"Input file not found: {input_path}")
                
            with self._progress_spinner(f"Importing entries from {input_path}..."):
                if format.lower() == "json":
                    data = json.loads(input_path.read_text())
                    for item in data:
                        entry = PasswordEntry.from_dict(item)
                        # Ensure we don't overwrite existing entries
                        entry.id = self.pm.generate_id()
                        self.pm.add_entry(entry)
                else:
                    raise ValueError(f"Unsupported import format: {format}")
                    
            console.print(f"[green]✓[/] Imported {len(data)} entries from {input_path}")
            
        except Exception as e:
            if self.debug:
                logger.exception("Error importing entries")
            raise click.ClickException(f"Failed to import entries: {e}")

def print_entry_table(entries: List[PasswordEntry]) -> None:
    """Print a table of password entries."""
    if not entries:
        console.print("[yellow]No entries found.[/]")
        return
        
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("ID", style="dim", width=8)
    table.add_column("Website")
    table.add_column("Username")
    table.add_column("Last Used", style="dim")
    table.add_column("Updated", style="dim")
    
    for entry in entries:
        table.add_row(
            entry.id[:8],
            entry.website,
            entry.username,
            entry.last_used.strftime("%Y-%m-%d") if entry.last_used else "Never",
            entry.updated_at.strftime("%Y-%m-%d") if entry.updated_at else ""
        )
        
    console.print(table)
