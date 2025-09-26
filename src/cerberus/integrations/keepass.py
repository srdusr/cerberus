"""KeePass integration for Cerberus."""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional, Dict, Any

from ..core.models import PasswordEntry
from . import BaseIntegration, register_integration, IntegrationError

try:
    import pykeepass
    KEEPASS_AVAILABLE = True
except ImportError:
    KEEPASS_AVAILABLE = False

@register_integration("keepass")
class KeePassIntegration(BaseIntegration):
    """Integration with KeePass password manager."""
    
    def __init__(self, database_path: Optional[Path] = None, keyfile: Optional[Path] = None):
        """Initialize the KeePass integration.
        
        Args:
            database_path: Path to the KeePass database file (.kdbx)
            keyfile: Path to the keyfile (if used)
        """
        super().__init__()
        if not KEEPASS_AVAILABLE:
            raise IntegrationError(
                "pykeepass package is required for KeePass integration. "
                "Install with: pip install pykeepass"
            )
            
        self.database_path = database_path
        self.keyfile = keyfile
        self.kp = None
    
    def connect(self, password: str, database_path: Optional[Path] = None, 
               keyfile: Optional[Path] = None, **kwargs) -> bool:
        """Connect to a KeePass database.
        
        Args:
            password: Database password
            database_path: Path to the KeePass database file
            keyfile: Path to the keyfile (if used)
            
        Returns:
            bool: True if connection was successful
        """
        if database_path:
            self.database_path = Path(database_path)
        if keyfile:
            self.keyfile = Path(keyfile)
        
        if not self.database_path or not self.database_path.exists():
            raise IntegrationError("KeePass database file not found")
        
        try:
            self.kp = pykeepass.PyKeePass(
                self.database_path,
                password=password,
                keyfile=str(self.keyfile) if self.keyfile and self.keyfile.exists() else None
            )
            self.connected = True
            return True
        except Exception as e:
            raise IntegrationError(f"Failed to open KeePass database: {e}")
    
    def disconnect(self):
        """Close the KeePass database."""
        self.kp = None
        self.connected = False
    
    def list_entries(self) -> List[PasswordEntry]:
        """List all password entries from the KeePass database.
        
        Returns:
            List of PasswordEntry objects
            
        Raises:
            IntegrationError: If not connected or error reading the database
        """
        if not self.connected or not self.kp:
            raise IntegrationError("Not connected to KeePass database")
        
        entries: List[PasswordEntry] = []
        
        try:
            for entry in self.kp.entries:
                # Skip entries without URLs or usernames
                if not (entry.url or entry.title) or not entry.username:
                    continue
                
                # Get entry notes and custom fields
                notes = entry.notes or ""
                custom_fields = {}
                
                # Add any custom fields
                for key, value in entry.custom_properties.items():
                    if key and value and key.lower() not in ['notes', 'password']:
                        custom_fields[key] = value
                
                # Create a PasswordEntry
                entry_obj = PasswordEntry(
                    website=entry.url or entry.title,
                    username=entry.username,
                    password=entry.password,
                    notes=notes,
                    url=entry.url,
                    tags=[entry.group.name] if entry.group else [],
                    custom_fields=custom_fields if custom_fields else None
                )
                
                entries.append(entry_obj)
                
        except Exception as e:
            raise IntegrationError(f"Error reading KeePass database: {e}")
        
        return entries
    
    def import_entries(self, input_path: Optional[Path] = None, password: str = None, 
                      keyfile: Optional[Path] = None) -> List[PasswordEntry]:
        """Import entries from a KeePass database.
        
        Args:
            input_path: Path to the KeePass database file
            password: Database password
            keyfile: Path to the keyfile (if used)
            
        Returns:
            List of imported PasswordEntry objects
        """
        if input_path:
            self.database_path = Path(input_path)
        if keyfile:
            self.keyfile = Path(keyfile)
        
        if not password:
            raise IntegrationError("Password is required to open KeePass database")
        
        self.connect(password=password, database_path=self.database_path, keyfile=self.keyfile)
        return self.list_entries()
    
    def export_entries(self, output_path: Path, entries: List[PasswordEntry] = None) -> bool:
        """Export entries to a new KeePass database.
        
        Args:
            output_path: Path to save the new KeePass database
            entries: List of PasswordEntry objects to export
            
        Returns:
            bool: True if export was successful
        """
        if not self.connected or not self.kp:
            raise IntegrationError("Not connected to KeePass database")
        
        try:
            # Create a new KeePass database
            new_kp = pykeepass.create_database(str(output_path))
            
            # Add a group for the imported entries
            imported_group = new_kp.add_group(new_kp.root_group, 'Imported')
            
            # Add each entry to the database
            for entry in (entries or self.list_entries()):
                # Skip entries without URLs or usernames
                if not (entry.website or entry.url) or not entry.username:
                    continue
                
                # Add the entry to the database
                new_entry = new_kp.add_entry(
                    imported_group,
                    title=entry.website or entry.url,
                    username=entry.username,
                    password=entry.password,
                    url=entry.url or entry.website,
                    notes=entry.notes,
                    tags=','.join(entry.tags) if entry.tags else None
                )
                
                # Add custom fields
                if entry.custom_fields:
                    for key, value in entry.custom_fields.items():
                        if key and value and key.lower() not in ['notes', 'password']:
                            new_entry.set_custom_property(key, str(value))
            
            # Save the new database
            new_kp.save()
            return True
            
        except Exception as e:
            raise IntegrationError(f"Error exporting to KeePass database: {e}")

    @classmethod
    def export_help(cls) -> str:
        """Get instructions for exporting from KeePass.
        
        Returns:
            str: Instructions for exporting from KeePass
        """
        return """To export from KeePass:
        1. Open your KeePass database
        2. Go to 'File' > 'Export'
        3. Choose a format (e.g., XML)
        4. Save the exported file
        
        Note: For better security, use the direct database import method.
        """
