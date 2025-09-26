import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Union, Any
from datetime import datetime

logger = logging.getLogger(__name__)

# Import the C core from our package
try:
    from . import (
        cerb_crypto_init, cerb_crypto_cleanup,
        cerb_vault_create, cerb_vault_open, cerb_vault_save, cerb_vault_close,
        cerb_vault_add_entry_basic, cerb_vault_update_entry_basic, cerb_vault_delete_entry,
        cerb_vault_get_entry_basic, cerb_vault_get_entries_basic, cerb_vault_search_basic,
        cerb_generate_password, cerb_generate_uuid, cerb_current_timestamp,
        CERB_OK, CERB_ERROR, ffi
    )
    CORE_AVAILABLE = True
except (ImportError, OSError) as e:
    CORE_AVAILABLE = False
    logger.warning("Cerberus C core not available. Using Python fallback.")

from .models import PasswordEntry
from ..integrations import get_integration, IntegrationError

class VaultError(Exception):
    """Base exception for vault-related errors."""
    pass

class CoreNotAvailableError(VaultError):
    """Raised when the C core is not available."""
    pass

class PasswordManager:
    """Core password manager with C-based encryption and integration support."""
    
    def __init__(self, data_dir: str = None, master_password: str = None):
        """Initialize the password manager.
        
        Args:
            data_dir: Directory to store password data
            master_password: Master password for encryption
        """
        if not CORE_AVAILABLE:
            raise CoreNotAvailableError(
                "Cerberus C core not available. Please compile it first."
            )
        
        self.data_dir = Path(data_dir or os.path.expanduser("~/.cerberus_pm"))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.master_password = master_password
        self.vault_file = self.data_dir / "vault.cerb"
        self._vault = ffi.NULL
        
        # Initialize crypto
        if cerb_crypto_init() != CERB_OK:
            raise VaultError("Failed to initialize crypto")
        
        # Create or load vault if master password is provided
        if master_password:
            if self.vault_file.exists():
                self._open_vault()
            else:
                self._create_vault()
    
    def _create_vault(self):
        """Create a new vault."""
        if not self.master_password:
            raise VaultError("Master password is required to create a vault")
        
        vault_ptr = ffi.new("cerb_vault_t**")
        result = cerb_vault_create(
            self.master_password.encode('utf-8'),
            vault_ptr
        )
        
        if result != CERB_OK:
            raise VaultError(f"Failed to create vault: error code {result}")
        
        self._vault = vault_ptr[0]
        logger.info("Created new vault")
    
    def _open_vault(self):
        """Open an existing vault."""
        if not self.vault_file.exists():
            raise VaultError(f"Vault file not found: {self.vault_file}")
        
        if not self.master_password:
            raise VaultError("Master password is required to open the vault")
        
        # Open existing vault from file using C core
        vault_ptr = ffi.new("cerb_vault_t**")
        result = cerb_vault_open(
            self.master_password.encode('utf-8'),
            str(self.vault_file).encode('utf-8'),
            vault_ptr
        )
        if result != CERB_OK:
            raise VaultError(f"Failed to open vault: error code {result}")
        self._vault = vault_ptr[0]
    
    def save_vault(self):
        """Save the vault to disk."""
        if self._vault == ffi.NULL:
            raise VaultError("No vault is open")
        
        result = cerb_vault_save(self._vault, str(self.vault_file).encode('utf-8'))
        if result != CERB_OK:
            raise VaultError(f"Failed to save vault: error code {result}")
    
    def initialize(self, master_password: str) -> bool:
        """Initialize the password manager with a master password.
        
        Args:
            master_password: The master password
            
        Returns:
            bool: True if initialization was successful
        """
        self.master_password = master_password
        self._create_vault()
        return True
    
    def unlock(self, master_password: str) -> bool:
        """Unlock the password manager with the master password.
        
        Args:
            master_password: The master password
            
        Returns:
            bool: True if unlock was successful
        """
        try:
            self.master_password = master_password
            self._open_vault()
            return True
        except VaultError as e:
            logger.error(f"Failed to unlock password manager: {e}")
            return False
    
    def _find_entries(self, query: str = None) -> List[PasswordEntry]:
        """Find entries matching the query.
        
        Args:
            query: Search query (e.g., 'website:example.com', 'tag:work')
            
        Returns:
            List of matching PasswordEntry objects
        """
        if self._vault == ffi.NULL:
            raise VaultError("No vault is open")
        
        entries_ptr = ffi.new("cerb_entry_basic_t**")
        count_ptr = ffi.new("size_t*")
        if query:
            result = cerb_vault_search_basic(self._vault, query.encode('utf-8'), entries_ptr, count_ptr)
        else:
            result = cerb_vault_get_entries_basic(self._vault, entries_ptr, count_ptr)
        if result != CERB_OK:
            raise VaultError(f"Search failed: error code {result}")

        results: List[PasswordEntry] = []
        count = int(count_ptr[0])
        if count == 0:
            return results

        entries_array = entries_ptr[0]
        for i in range(count):
            c_entry = entries_array[i]
            results.append(PasswordEntry(
                id=ffi.string(c_entry.id).decode('utf-8'),
                website=ffi.string(c_entry.website).decode('utf-8'),
                username=ffi.string(c_entry.username).decode('utf-8'),
                password=ffi.string(c_entry.password).decode('utf-8'),
                url=ffi.string(c_entry.url).decode('utf-8'),
                notes=ffi.string(c_entry.notes).decode('utf-8'),
            ))

        # Caller-owned memory: free via C if a free function exists; else rely on C API contract
        return results
    
    def add_password(self, entry: PasswordEntry) -> str:
        """Add a new password entry to the vault.
        
        Args:
            entry: The password entry to add
            
        Returns:
            str: The ID of the new entry
            
        Raises:
            VaultError: If the vault is not open or an error occurs
        """
        if self._vault == ffi.NULL:
            raise VaultError("No vault is open")
        
        # Create a new C entry
        c_entry = ffi.new("cerb_entry_basic_t*")

        # Generate a new UUID if not provided
        if entry.id:
            entry_id = entry.id
        else:
            uuid_buf = ffi.new("char[37]")
            cerb_generate_uuid(uuid_buf)
            entry_id = ffi.string(uuid_buf).decode('utf-8')

        # Set fields
        ffi.memmove(c_entry.id, entry_id.encode('utf-8'), len(entry_id))
        c_entry.id[len(entry_id)] = b'\0'
        for field_name in ["website", "username", "password", "notes", "url"]:
            val = (getattr(entry, field_name) or '').encode('utf-8')
            buf = getattr(c_entry, field_name)
            ffi.memmove(buf, val, len(val))
            buf[len(val)] = b'\0'
        c_entry.created_at = int(entry.created_at.timestamp()) if entry.created_at else cerb_current_timestamp()
        c_entry.updated_at = int(entry.updated_at.timestamp()) if entry.updated_at else c_entry.created_at
        
        # Add to vault
        result = cerb_vault_add_entry_basic(self._vault, c_entry)
        if result != CERB_OK:
            raise VaultError(f"Failed to add entry: error code {result}")
        
        # Save the vault
        self.save_vault()
        
        return entry_id
    
    def update_password(self, entry_id: str, **updates) -> bool:
        """Update an existing password entry.
        
        Args:
            entry_id: The ID of the entry to update
            **updates: Fields to update
            
        Returns:
            bool: True if the update was successful
            
        Raises:
            VaultError: If the vault is not open or an error occurs
            ValueError: If the entry is not found
        """
        if self._vault == ffi.NULL:
            raise VaultError("No vault is open")
        
        # Fetch, modify, send to C update
        c_existing = ffi.new("cerb_entry_basic_t*")
        res = cerb_vault_get_entry_basic(self._vault, entry_id.encode('utf-8'), c_existing)
        if res != CERB_OK:
            raise ValueError(f"Entry with ID {entry_id} not found")

        # Apply updates
        def _set_field(dst, value: str, max_len: int):
            data = (value or '').encode('utf-8')
            ln = min(len(data), max_len - 1)
            ffi.memmove(dst, data, ln)
            dst[ln] = b'\0'

        for key, value in updates.items():
            if key == 'website': _set_field(c_existing.website, value, 256)
            elif key == 'username': _set_field(c_existing.username, value, 256)
            elif key == 'password': _set_field(c_existing.password, value, 1024)
            elif key == 'notes': _set_field(c_existing.notes, value, 4096)
            elif key == 'url': _set_field(c_existing.url, value, 1024)

        c_existing.updated_at = int(datetime.utcnow().timestamp())

        res = cerb_vault_update_entry_basic(self._vault, c_existing)
        if res != CERB_OK:
            raise VaultError(f"Failed to update entry: error code {res}")
        self.save_vault()
        return True
    
    def delete_password(self, entry_id: str) -> bool:
        """Delete a password entry.
        
        Args:
            entry_id: The ID of the entry to delete
            
        Returns:
            bool: True if the deletion was successful
            
        Raises:
            VaultError: If the vault is not open or an error occurs
        """
        if self._vault == ffi.NULL:
            raise VaultError("No vault is open")
        
        result = cerb_vault_delete_entry(self._vault, entry_id.encode('utf-8'))
        if result != CERB_OK:
            raise VaultError(f"Failed to delete entry: error code {result}")
        
        # Save the vault
        self.save_vault()
        return True
    
    def get_password(self, entry_id: str) -> Optional[PasswordEntry]:
        """Get a password entry by ID.
        
        Args:
            entry_id: The ID of the entry to retrieve
            
        Returns:
            PasswordEntry if found, None otherwise
        """
        c_entry = ffi.new("cerb_entry_basic_t*")
        res = cerb_vault_get_entry_basic(self._vault, entry_id.encode('utf-8'), c_entry)
        if res != CERB_OK:
            return None
        return PasswordEntry(
            id=ffi.string(c_entry.id).decode('utf-8'),
            website=ffi.string(c_entry.website).decode('utf-8'),
            username=ffi.string(c_entry.username).decode('utf-8'),
            password=ffi.string(c_entry.password).decode('utf-8'),
            url=ffi.string(c_entry.url).decode('utf-8'),
            notes=ffi.string(c_entry.notes).decode('utf-8'),
        )
    
    def list_passwords(self) -> List[PasswordEntry]:
        """List all password entries.
        
        Returns:
            List of all PasswordEntry objects
        """
        return self._find_entries()
    
    def search_passwords(self, query: str) -> List[PasswordEntry]:
        """Search password entries by website, username, or tags.
        
        Args:
            query: Search query
            
        Returns:
            List of matching PasswordEntry objects
        """
        return self._find_entries(query)
    
    @staticmethod
    def generate_password(
        length: int = 16,
        use_upper: bool = True,
        use_lower: bool = True,
        use_digits: bool = True,
        use_special: bool = True
    ) -> str:
        """Generate a secure random password using the C core.
        
        Args:
            length: Length of the password (8-1024)
            use_upper: Include uppercase letters
            use_lower: Include lowercase letters
            use_digits: Include digits
            use_special: Include special characters
            
        Returns:
            The generated password
            
        Raises:
            VaultError: If password generation fails
        """
        if not CORE_AVAILABLE:
            raise CoreNotAvailableError("C core not available for password generation")
        
        # Validate length
        if length < 8 or length > 1024:
            raise ValueError("Password length must be between 8 and 1024 characters")
        
        # At least one character set must be selected
        if not (use_upper or use_lower or use_digits or use_special):
            raise ValueError("At least one character set must be selected")
        
        # Allocate buffer for the password (+1 for null terminator)
        buffer = ffi.new(f"char[{length + 1}]")  # +1 for null terminator
        
        # Generate the password
        result = cerb_generate_password(
            length,
            use_upper,
            use_lower,
            use_digits,
            use_special,
            buffer,
            length + 1  # Include space for null terminator
        )
        
        if result != CERB_OK:
            raise VaultError(f"Failed to generate password: error code {result}")
        
        # Convert from C string to Python string
        password = ffi.string(buffer).decode('utf-8')
        return password

    # ---- Convenience methods for CLI/TUI compatibility ----
    def generate_id(self) -> str:
        """Generate a UUID string using the C core."""
        if not CORE_AVAILABLE:
            raise CoreNotAvailableError("C core not available for ID generation")
        uuid_buf = ffi.new("char[37]")
        cerb_generate_uuid(uuid_buf)
        return ffi.string(uuid_buf).decode("utf-8")

    def get_entries(self) -> List[PasswordEntry]:
        """Alias for list_passwords()."""
        return self.list_passwords()

    def add_entry(self, entry: PasswordEntry) -> str:
        """Alias for add_password(entry)."""
        return self.add_password(entry)

    def update_entry(self, entry: PasswordEntry) -> bool:
        """Update an existing entry using the entry object."""
        fields = {
            "website": entry.website,
            "username": entry.username,
            "password": entry.password,
            "notes": entry.notes,
            "url": entry.url,
        }
        return self.update_password(entry.id, **fields)

    def delete_entry(self, entry_id: str) -> bool:
        """Alias for delete_password(entry_id)."""
        return self.delete_password(entry_id)

    def get_entry(self, identifier: str) -> PasswordEntry:
        """Get an entry by ID, or by exact website match as a fallback."""
        entry = self.get_password(identifier)
        if entry is not None:
            return entry
        # Fallback: search by exact website name
        matches = [e for e in self.list_passwords() if (e.website or "").lower() == (identifier or "").lower()]
        if not matches:
            raise ValueError(f"Entry not found: {identifier}")
        if len(matches) > 1:
            raise ValueError(f"Multiple entries found for website '{identifier}'. Use the entry ID instead.")
        return matches[0]

    def generate_password_easy(
        self,
        length: int = 16,
        special: bool = True,
        upper: Optional[bool] = None,
        lower: Optional[bool] = None,
        digits: Optional[bool] = None,
    ) -> str:
        """Friendly wrapper for password generation used by new CLI/TUI.

        Args:
            length: desired length
            special: include special characters (maps to use_special)
            upper, lower, digits: if None use defaults (True). If bool provided, override.
        """
        return PasswordManager.generate_password(
            length=length,
            use_upper=True if upper is None else upper,
            use_lower=True if lower is None else lower,
            use_digits=True if digits is None else digits,
            use_special=special,
        )
