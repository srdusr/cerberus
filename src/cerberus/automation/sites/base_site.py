from typing import Protocol, Optional, Dict, Any

from ...core.models import PasswordEntry
from ..types import AutomationResult


class SiteFlow(Protocol):
    def match(self, entry: PasswordEntry) -> bool:
        ...

    def perform_change(self, engine, entry: PasswordEntry, new_password: str, options: Optional[Dict[str, Any]] = None) -> AutomationResult:
        ...


