"""LastPass integration for Cerberus."""

import csv
from pathlib import Path
from typing import List, Optional, Dict, Any

from ..core.models import PasswordEntry
from . import BaseIntegration, register_integration, IntegrationError

@register_integration("lastpass")
class LastPassIntegration(BaseIntegration):
    """Integration with LastPass password manager."""
    
    def __init__(self, export_path: Optional[Path] = None):
        """Initialize the LastPass integration.
        
        Args:
            export_path: Path to LastPass export file
        """
        super().__init__()
        self.export_path = export_path
    
    def connect(self, export_path: Optional[Path] = None, **kwargs) -> bool:
        """Connect to LastPass (loads the export file).
        
        Args:
            export_path: Path to LastPass export file
            
        Returns:
            bool: True if the export file exists and is accessible
        """
        if export_path:
            self.export_path = Path(export_path)
        
        if not self.export_path or not self.export_path.exists():
            raise IntegrationError("LastPass export file not found")
        
        self.connected = True
        return True
    
    def list_entries(self) -> List[PasswordEntry]:
        """List all password entries from the LastPass export.
        
        Returns:
            List of PasswordEntry objects
            
        Raises:
            IntegrationError: If not connected or error reading the export file
        """
        if not self.connected:
            raise IntegrationError("Not connected to LastPass")
        
        entries: List[PasswordEntry] = []
        
        try:
            with open(self.export_path, 'r', encoding='utf-8') as f:
                # Skip the first line (header)
                next(f)
                
                reader = csv.reader(f)
                for row in reader:
                    if len(row) < 7:  # Ensure we have enough columns
                        continue
                    
                    url, username, password, extra, name, grouping, fav = row[:7]
                    
                    # Create a PasswordEntry
                    entry = PasswordEntry(
                        website=url or name or "Unknown",
                        username=username,
                        password=password,
                        notes=extra,
                        tags=[grouping] if grouping else []
                    )
                    
                    entries.append(entry)
                    
        except Exception as e:
            raise IntegrationError(f"Error reading LastPass export: {e}")
        
        return entries
    
    def import_entries(self, input_path: Optional[Path] = None) -> List[PasswordEntry]:
        """Import entries from a LastPass export file.
        
        Args:
            input_path: Path to the LastPass export file
            
        Returns:
            List of imported PasswordEntry objects
        """
        if input_path:
            self.export_path = Path(input_path)
        
        if not self.export_path or not self.export_path.exists():
            raise IntegrationError("LastPass export file not found")
        
        return self.list_entries()
    
    def export_entries(self, output_path: Path) -> bool:
        """Export entries to a LastPass-compatible CSV file.
        
        Args:
            output_path: Path to save the exported data
            
        Returns:
            bool: True if export was successful
        """
        # This would require converting from our format to LastPass format
        # For now, we'll just raise a NotImplementedError
        raise NotImplementedError("Export to LastPass format is not yet implemented")

    @classmethod
    def export_help(cls) -> str:
        """Get instructions for exporting from LastPass.
        
        Returns:
            str: Instructions for exporting from LastPass
        """
        return """To export from LastPass:
        1. Log in to your LastPass account
        2. Click on your email in the bottom left
        3. Select 'Advanced' > 'Export'
        4. Enter your master password
        5. Save the exported file
        """
