import subprocess
import json
import logging
from typing import List, Dict, Optional, Any
from pathlib import Path
import os

from ..core.models import PasswordEntry

logger = logging.getLogger(__name__)

class BitwardenCLIError(Exception):
    """Exception raised for errors in the Bitwarden CLI."""
    pass

class BitwardenIntegration:
    """Integration with Bitwarden password manager."""
    
    def __init__(self, email: str = None, password: str = None, session: str = None):
        """Initialize the Bitwarden integration.
        
        Args:
            email: Bitwarden account email
            password: Bitwarden master password
            session: Existing Bitwarden session key
        """
        self.email = email
        self.password = password
        self.session = session
        self.bw_path = self._find_bw()
        
    def _run_command(self, command: List[str], input_data: str = None) -> Dict:
        """Run a Bitwarden CLI command and return the result."""
        try:
            env = os.environ.copy()
            if self.session:
                env['BW_SESSION'] = self.session
                
            result = subprocess.run(
                [self.bw_path] + command,
                input=input_data.encode() if input_data else None,
                capture_output=True,
                check=True,
                env=env
            )
            
            if result.stdout:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    return result.stdout.decode().strip()
            return {}
            
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.decode().strip() if e.stderr else str(e)
            logger.error(f"Bitwarden CLI error: {error_msg}")
            raise BitwardenCLIError(f"Bitwarden command failed: {error_msg}")
    
    @staticmethod
    def _find_bw() -> str:
        """Find the Bitwarden CLI executable."""
        # Check common locations
        possible_paths = [
            '/usr/local/bin/bw',
            '/usr/bin/bw',
            'bw'  # Try PATH
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run(
                    [path, '--version'],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    logger.info(f"Found Bitwarden CLI at {path}")
                    return path
            except (FileNotFoundError, subprocess.CalledProcessError):
                continue
                
        raise BitwardenCLIError(
            "Bitwarden CLI not found. Please install it from "
            "https://bitwarden.com/help/cli/"
        )
    
    def login(self) -> bool:
        """Log in to Bitwarden and get a session key."""
        if not self.email or not self.password:
            raise BitwardenCLIError("Email and password are required for login")
            
        try:
            # Log in and get the session key
            result = subprocess.run(
                [self.bw_path, 'login', self.email, self.password, '--raw'],
                capture_output=True,
                check=True,
                text=True
            )
            
            self.session = result.stdout.strip()
            return True
            
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.decode().strip() if e.stderr else str(e)
            logger.error(f"Bitwarden login failed: {error_msg}")
            return False
    
    def logout(self) -> bool:
        """Log out of Bitwarden."""
        try:
            self._run_command(['logout'])
            self.session = None
            return True
        except BitwardenCLIError:
            return False
    
    def sync(self) -> bool:
        """Sync with Bitwarden server."""
        try:
            self._run_command(['sync'])
            return True
        except BitwardenCLIError:
            return False
    
    def export_vault(self, output_file: str, format: str = 'encrypted_json') -> bool:
        """Export the Bitwarden vault.
        
        Args:
            output_file: Path to save the exported file
            format: Export format ('encrypted_json', 'json', 'csv', 'encrypted_json')
            
        Returns:
            bool: True if export was successful
        """
        try:
            result = self._run_command(['export', '--format', format, '--output', output_file])
            return True
        except BitwardenCLIError:
            return False
    
    def get_items(self, search: str = None) -> List[Dict]:
        """Get items from the vault, optionally filtered by search term."""
        try:
            if search:
                return self._run_command(['list', 'items', '--search', search])
            return self._run_command(['list', 'items'])
        except BitwardenCLIError:
            return []
    
    def get_item(self, item_id: str) -> Optional[Dict]:
        """Get a specific item by ID."""
        try:
            return self._run_command(['get', 'item', item_id])
        except BitwardenCLIError:
            return None
    
    def create_item(self, item_data: Dict) -> Optional[Dict]:
        """Create a new item in the vault."""
        try:
            return self._run_command(
                ['create', 'item'],
                input_data=json.dumps(item_data)
            )
        except BitwardenCLIError:
            return None
    
    def update_item(self, item_id: str, item_data: Dict) -> Optional[Dict]:
        """Update an existing item."""
        try:
            return self._run_command(
                ['edit', 'item', item_id],
                input_data=json.dumps(item_data)
            )
        except BitwardenCLIError:
            return None
    
    def delete_item(self, item_id: str) -> bool:
        """Delete an item from the vault."""
        try:
            self._run_command(['delete', 'item', item_id])
            return True
        except BitwardenCLIError:
            return False
    
    def import_from_bitwarden(self) -> List[PasswordEntry]:
        """Import passwords from Bitwarden to Cerberus format."""
        try:
            items = self.get_items()
            entries = []
            
            for item in items:
                try:
                    entry = PasswordEntry(
                        id=item.get('id'),
                        website=item.get('name', ''),
                        username=next(
                            (field['value'] for field in item.get('login', {}).get('uris', [{}]) 
                             if field.get('name', '').lower() == 'username'),
                            ''
                        ),
                        password=item.get('login', {}).get('password', ''),
                        url=next(
                            (uri.get('uri', '') for uri in item.get('login', {}).get('uris', []) 
                             if uri.get('uri')),
                            ''
                        ),
                        notes=item.get('notes', ''),
                        tags=item.get('collectionIds', []),
                        custom_fields={
                            'folderId': item.get('folderId'),
                            'organizationId': item.get('organizationId'),
                            'favorite': item.get('favorite', False),
                            'reprompt': item.get('reprompt', 0),
                            'revisionDate': item.get('revisionDate')
                        }
                    )
                    entries.append(entry)
                except Exception as e:
                    logger.error(f"Error converting Bitwarden item to PasswordEntry: {e}")
            
            return entries
            
        except Exception as e:
            logger.error(f"Error importing from Bitwarden: {e}")
            return []
    
    def export_to_bitwarden(self, entries: List[PasswordEntry], folder_id: str = None) -> List[str]:
        """Export passwords from Cerberus format to Bitwarden.
        
        Args:
            entries: List of PasswordEntry objects to export
            folder_id: Optional Bitwarden folder ID to place items in
            
        Returns:
            List of Bitwarden item IDs that were created
        """
        created_ids = []
        
        for entry in entries:
            try:
                item_data = {
                    'type': 1,  # Login type
                    'name': entry.website,
                    'notes': entry.notes,
                    'favorite': entry.custom_fields.get('favorite', False),
                    'login': {
                        'username': entry.username,
                        'password': entry.password,
                        'uris': [
                            {
                                'match': None,
                                'uri': entry.url
                            }
                        ] if entry.url else []
                    },
                    'collectionIds': entry.tags,
                    'folderId': folder_id or entry.custom_fields.get('folderId')
                }
                
                result = self.create_item(item_data)
                if result and 'id' in result:
                    created_ids.append(result['id'])
                    
            except Exception as e:
                logger.error(f"Error exporting entry to Bitwarden: {e}")
        
        return created_ids
