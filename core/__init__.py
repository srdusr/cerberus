"""Cerberus Core - Core functionality for the Cerberus password manager.

This module provides the core functionality for the Cerberus password manager,
including the C core bindings and high-level password management interfaces.
"""

import os
import cffi
from pathlib import Path
from typing import Optional, Any

# Initialize CFFI (exported for callers that need to manage buffers)
ffi = cffi.FFI()

# Load the C header
def _load_header():
    header_path = Path(__file__).parent / 'cerberus.h'
    with open(header_path) as f:
        # Read and clean up the header for CFFI
        lines = []
        for line in f:
            # Remove #include directives and other preprocessor commands
            if line.startswith('#'):
                continue
            # Remove C++ style comments
            if '//' in line:
                line = line.split('//')[0] + '\n'
            lines.append(line)
        
        # Join the cleaned lines and pass to cdef
        ffi.cdef('\n'.join(filter(None, lines)))

# Load the header
_load_header()

# Try to load the compiled library
_lib = None

def init() -> bool:
    """Initialize the Cerberus C core.
    
    Returns:
        bool: True if initialization was successful, False otherwise
    """
    global _lib
    
    if _lib is not None:
        return True
        
    # Try multiple candidate names
    candidates = [
        Path(__file__).parent / 'libcerberus.so',
        Path(__file__).parent / 'cerberus.so'
    ]
    for lib_path in candidates:
        try:
            _lib = ffi.dlopen(str(lib_path))
            return True
        except OSError:
            continue
    _lib = None
    return False

# Initialize on import
if not init():
    class DummyLib:
        def __getattribute__(self, name: str) -> Any:
            raise RuntimeError(
                "Cerberus C core not initialized. "
                "Please ensure the core is compiled and in your library path."
            )
    
    _lib = DummyLib()

# Re-export the C functions with proper typing
for name in dir(_lib):
    if name.startswith('cerb_'):
        globals()[name] = getattr(_lib, name)

# Clean up the namespace (keep ffi exported)
del os, Path, _load_header, init, DummyLib

# Export high-level interfaces
from .password_manager import PasswordManager
from .models import PasswordEntry

__all__ = [
    'PasswordManager',
    'PasswordEntry',
    'VaultError',
    'CoreNotAvailableError',
    'ffi'
]
