""
Main TUI application for Cerberus Password Manager.
"""
from typing import Optional, List, Dict, Any
from pathlib import Path
import logging

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.traceback import install as install_rich_traceback
from textual.app import App, ComposeResult
from textual.containers import Container, VerticalScroll
from textual.widgets import (
    Header, Footer, Button, Static, Input, Label, 
    DataTable, Select, Switch, LoadingIndicator
)

from ..core.password_manager import PasswordManager, VaultError
from ..core.models import PasswordEntry

# Set up rich traceback for better error messages
install_rich_traceback(show_locals=True)
logger = logging.getLogger(__name__)

class CerberusTUI(App):
    """Main TUI application for Cerberus Password Manager."""
    
    CSS = """
    Screen {
        layout: vertical;
    }
    
    #login-screen {
        width: 100%;
        height: 100%;
        align: center middle;
    }
    
    #main-screen {
        width: 100%;
        height: 100%;
        layout: horizontal;
    }
    
    #sidebar {
        width: 30%;
        height: 100%;
        border: solid $accent;
    }
    
    #content {
        width: 70%;
        height: 100%;
        border: solid $accent;
    }
    
    .entry-list {
        width: 100%;
        height: 100%;
    }
    
    .entry-detail {
        width: 100%;
        height: 100%;
        padding: 1;
    }
    """
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("n", "new_password", "New Password"),
        ("f", "find", "Find Password"),
        ("r", "refresh", "Refresh"),
        ("c", "copy_password", "Copy Password"),
        ("u", "copy_username", "Copy Username"),
        ("d", "delete", "Delete Entry"),
    ]
    
    def __init__(self, data_dir: Optional[str] = None, **kwargs):
        super().__init__(**kwargs)
        self.console = Console()
        self.pm: Optional[PasswordManager] = None
        self.data_dir = data_dir
        self.current_entry: Optional[PasswordEntry] = None
        self.entries: List[PasswordEntry] = []
    
    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        if not self.pm:
            yield Container(
                VerticalScroll(
                    Label("🔒 Cerberus Password Manager", id="login-title"),
                    Input(placeholder="Master Password", password=True, id="master-password"),
                    Button("Unlock", variant="primary", id="unlock-button"),
                    id="login-screen"
                )
            )
        else:
            with Container(id="main-screen"):
                with Container(id="sidebar"):
                    yield DataTable(id="entry-list", cursor_type="row")
                with Container(id="content"):
                    yield Static("Select an entry to view details", id="entry-detail")
    
    def on_mount(self) -> None:
        """Initialize the UI after mounting."""
        if not self.pm:
            self.query_one("#master-password", Input).focus()
        else:
            self.load_entries()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events."""
        if event.button.id == "unlock-button":
            self.unlock_vault()
    
    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle input submission."""
        if event.input.id == "master-password":
            self.unlock_vault()
    
    def unlock_vault(self) -> None:
        """Attempt to unlock the password vault."""
        password_input = self.query_one("#master-password", Input)
        password = password_input.value
        
        if not password:
            self.notify("Please enter a master password", severity="error")
            return
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
                console=self.console
            ) as progress:
                task = progress.add_task("Unlocking vault...", total=None)
                self.pm = PasswordManager(data_dir=self.data_dir, master_password=password)
                progress.update(task, completed=1)
            
            # Clear the login screen and show the main interface
            self.query("#login-screen").remove()
            self.compose()
            self.load_entries()
            
        except VaultError as e:
            self.notify(f"Failed to unlock vault: {e}", severity="error")
        except Exception as e:
            logger.exception("Error unlocking vault")
            self.notify(f"An error occurred: {e}", severity="error")
    
    def load_entries(self) -> None:
        """Load password entries into the UI."""
        if not self.pm:
            return
            
        try:
            table = self.query_one("#entry-list", DataTable)
            table.clear()
            table.add_columns("Website", "Username", "Last Used")
            
            self.entries = self.pm.get_entries()
            for entry in self.entries:
                table.add_row(
                    entry.website,
                    entry.username,
                    entry.last_used.strftime("%Y-%m-%d") if entry.last_used else "Never"
                )
                
        except Exception as e:
            logger.exception("Error loading entries")
            self.notify(f"Failed to load entries: {e}", severity="error")
    
    def action_new_password(self) -> None:
        """Create a new password entry."""
        self.notify("New password functionality coming soon!", severity="information")
    
    def action_find(self) -> None:
        """Find a password entry."""
        self.notify("Find functionality coming soon!", severity="information")
    
    def action_refresh(self) -> None:
        """Refresh the entry list."""
        self.load_entries()
        self.notify("Entries refreshed", severity="information")
    
    def action_copy_password(self) -> None:
        """Copy the current entry's password to clipboard."""
        if not self.current_entry:
            self.notify("No entry selected", severity="warning")
            return
            
        try:
            # Use platform-specific clipboard handling
            import pyperclip
            pyperclip.copy(self.current_entry.password)
            self.notify("Password copied to clipboard", severity="information")
        except Exception as e:
            logger.exception("Error copying to clipboard")
            self.notify(f"Failed to copy to clipboard: {e}", severity="error")
    
    def action_copy_username(self) -> None:
        """Copy the current entry's username to clipboard."""
        if not self.current_entry:
            self.notify("No entry selected", severity="warning")
            return
            
        try:
            import pyperclip
            pyperclip.copy(self.current_entry.username)
            self.notify("Username copied to clipboard", severity="information")
        except Exception as e:
            logger.exception("Error copying username")
            self.notify(f"Failed to copy username: {e}", severity="error")
    
    def action_delete(self) -> None:
        """Delete the current entry."""
        if not self.current_entry:
            self.notify("No entry selected", severity="warning")
            return
            
        if Confirm.ask(f"Delete entry for {self.current_entry.website}?"):
            try:
                self.pm.delete_entry(self.current_entry.id)
                self.load_entries()
                self.notify("Entry deleted", severity="information")
                self.current_entry = None
                self.query_one("#entry-detail", Static).update("Select an entry to view details")
            except Exception as e:
                logger.exception("Error deleting entry")
                self.notify(f"Failed to delete entry: {e}", severity="error")

def main():
    """Run the Cerberus TUI."""
    app = CerberusTUI()
    app.run()

if __name__ == "__main__":
    main()
