"""Password manager integrations for Cerberus."""

from typing import Dict, Type, List, Optional, Any
from pathlib import Path
import importlib
import json

from ..core.models import PasswordEntry

class IntegrationError(Exception):
    """Base exception for integration errors."""
    pass

class BaseIntegration:
    """Base class for password manager integrations."""
    
    def __init__(self, **kwargs):
        """Initialize the integration with any required parameters."""
        self.connected = False
    
    def connect(self, **kwargs) -> bool:
        """Connect to the password manager.
        
        Returns:
            bool: True if connection was successful
        """
        raise NotImplementedError
    
    def disconnect(self):
        """Disconnect from the password manager."""
        self.connected = False
    
    def list_entries(self) -> List[PasswordEntry]:
        """List all password entries.
        
        Returns:
            List of PasswordEntry objects
        """
        raise NotImplementedError
    
    def export_entries(self, output_path: Path) -> bool:
        """Export entries to a file.
        
        Args:
            output_path: Path to save the exported data
            
        Returns:
            bool: True if export was successful
        """
        raise NotImplementedError
    
    def import_entries(self, input_path: Path) -> List[PasswordEntry]:
        """Import entries from a file.
        
        Args:
            input_path: Path to the file to import from
            
        Returns:
            List of imported PasswordEntry objects
        """
        raise NotImplementedError

# Dictionary of available integrations
INTEGRATIONS: Dict[str, Type[BaseIntegration]] = {}

def register_integration(name: str):
    """Decorator to register an integration class."""
    def decorator(cls: Type[BaseIntegration]) -> Type[BaseIntegration]:
        INTEGRATIONS[name.lower()] = cls
        return cls
    return decorator

def get_integration(name: str, **kwargs) -> BaseIntegration:
    """Get an instance of the specified integration.
    
    Args:
        name: Name of the integration
        **kwargs: Additional arguments to pass to the integration
        
    Returns:
        An instance of the specified integration
        
    Raises:
        IntegrationError: If the integration is not found
    """
    name = name.lower()
    if name not in INTEGRATIONS:
        raise IntegrationError(f"Integration '{name}' not found")
    
    return INTEGRATIONS[name](**kwargs)

def list_available_integrations() -> List[str]:
    """List all available integrations.
    
    Returns:
        List of integration names
    """
    return list(INTEGRATIONS.keys())

# Import all integration modules to register them
# This will be populated by the individual integration modules
# that use the @register_integration decorator

try:
    from . import bitwarden  # noqa
    from . import lastpass  # noqa
    from . import keepass  # noqa
    from . import chrome  # noqa
except ImportError as e:
    # Some integrations may have additional dependencies
    pass
