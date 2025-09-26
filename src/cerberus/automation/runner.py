from dataclasses import dataclass
from typing import List, Optional, Callable
from datetime import datetime

from ..core.password_manager import PasswordManager
from ..core.models import PasswordEntry
from .types import AutomationResult, AutomationStatus
from .discovery import auto_change_flow


@dataclass
class RotationSelector:
    all: bool = False
    compromised_only: bool = False
    tag: Optional[str] = None
    domain: Optional[str] = None


class RotationRunner:
    def __init__(self, engine, site_flows: List, password_manager: PasswordManager):
        self.engine = engine
        self.site_flows = site_flows
        self.pm = password_manager

    def _filter_entries(self, selector: RotationSelector) -> List[PasswordEntry]:
        entries = self.pm.list_passwords()
        filtered: List[PasswordEntry] = []
        for e in entries:
            if selector.compromised_only and not e.compromised:
                continue
            if selector.tag and selector.tag not in (e.tags or []):
                continue
            if selector.domain and selector.domain not in (e.url or e.website or ""):
                continue
            filtered.append(e)
        return filtered

    def rotate(self, selector: RotationSelector, generate_password: Callable[[PasswordEntry], str], dry_run: bool = True) -> List[AutomationResult]:
        results: List[AutomationResult] = []
        targets = self._filter_entries(selector)
        for entry in targets:
            new_password = generate_password(entry)
            if dry_run:
                results.append(AutomationResult(status=AutomationStatus.SUCCESS, message="dry-run", changed_at=datetime.utcnow()))
                continue

            flow = next((f for f in self.site_flows if f.match(entry)), None)
            if flow:
                res = flow.perform_change(self.engine, entry, new_password)
            else:
                # Fallback to heuristic auto discovery/change
                res = auto_change_flow(self.engine, entry, new_password)
            if res.status == AutomationStatus.SUCCESS:
                self.pm.update_password(entry.id, password=new_password)
            results.append(res)

        return results


