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

def _load_header():
    cdef_src = '''
        typedef unsigned int uint32_t;
        typedef unsigned long size_t;
        typedef long time_t;
        typedef int bool;

        typedef struct cerb_vault_t cerb_vault_t;
        typedef struct cerb_entry_t cerb_entry_t;

        typedef struct {
            char id[37];
            char website[256];
            char username[256];
            char password[1024];
            char notes[4096];
            char url[1024];
            time_t created_at;
            time_t updated_at;
        } cerb_entry_basic_t;

        int cerb_crypto_init(void);
        void cerb_crypto_cleanup(void);

        int cerb_vault_create(const char *master_password, cerb_vault_t **vault);
        int cerb_vault_open(const char *master_password, const char *vault_path, cerb_vault_t **vault);
        int cerb_vault_save(cerb_vault_t *vault, const char *vault_path);
        void cerb_vault_close(cerb_vault_t *vault);

        int cerb_vault_add_entry_basic(cerb_vault_t *vault, const cerb_entry_basic_t *entry);
        int cerb_vault_update_entry_basic(cerb_vault_t *vault, const cerb_entry_basic_t *entry);
        int cerb_vault_delete_entry(cerb_vault_t *vault, const char *entry_id);
        int cerb_vault_get_entry_basic(cerb_vault_t *vault, const char *entry_id, cerb_entry_basic_t *entry);
        int cerb_vault_get_entries_basic(cerb_vault_t *vault, cerb_entry_basic_t **entries, size_t *count);
        int cerb_vault_search_basic(cerb_vault_t *vault, const char *query, cerb_entry_basic_t **results, size_t *count);

        int cerb_generate_password(uint32_t length, bool use_upper, bool use_lower, bool use_digits, bool use_special, char *buffer, size_t buffer_size);
        void cerb_generate_uuid(char *uuid);
        time_t cerb_current_timestamp(void);
    '''
    ffi.cdef(cdef_src)

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
    class _DummyLib:
        def __getattribute__(self, name: str) -> Any:
            raise RuntimeError(
                "Cerberus C core not initialized. "
                "Please ensure the core is compiled and in your library path."
            )
    _lib = _DummyLib()
    CORE_AVAILABLE = False
else:
    CORE_AVAILABLE = True

# Re-export the C functions with proper typing
for name in dir(_lib):
    if name.startswith('cerb_'):
        globals()[name] = getattr(_lib, name)

# Error code constants (must match cerberus.h enum)
CERB_OK = 0
CERB_ERROR = -1

# Clean up the namespace (keep ffi exported)
try:
    del _DummyLib
except NameError:
    pass
del os, Path, _load_header, init

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
