# Avoid importing heavy submodules at top-level to prevent side effects
__all__ = ["PasswordManager", "PasswordEntry"]

def __getattr__(name):
    if name == "PasswordManager":
        from .core.password_manager import PasswordManager
        return PasswordManager
    if name == "PasswordEntry":
        from .core.models import PasswordEntry
        return PasswordEntry
    raise AttributeError(name)
