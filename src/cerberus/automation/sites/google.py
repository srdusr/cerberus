from typing import Optional, Dict, Any
from datetime import datetime

from ...core.models import PasswordEntry
from ..types import AutomationResult, AutomationStatus
from .base_site import SiteFlow


class GoogleFlow(SiteFlow):
    def match(self, entry: PasswordEntry) -> bool:
        target = (entry.url or entry.website or "").lower()
        return "google.com" in target

    def perform_change(self, engine, entry: PasswordEntry, new_password: str, options: Optional[Dict[str, Any]] = None) -> AutomationResult:
        try:
            # Login flow
            engine.goto("https://accounts.google.com/signin/v2/identifier")
            engine.wait_for("input[type=email], input#identifierId")
            try:
                engine.type("input[type=email], input#identifierId", entry.username)
            except Exception:
                pass
            engine.click("#identifierNext, button[type=submit]")
            try:
                engine.wait_for("input[type=password]", timeout_ms=7000)
            except Exception:
                return AutomationResult(status=AutomationStatus.NEEDS_MFA, message="MFA or challenge present")
            engine.type("input[type=password]", entry.password)
            engine.click("#passwordNext, button[type=submit]")

            # Security settings - direct link (subject to change)
            engine.goto("https://myaccount.google.com/signinoptions/password")
            engine.wait_for("input[type=password]")
            engine.type("input[type=password]", entry.password)
            engine.click("button[type=submit], #passwordNext")

            # New password fields
            engine.wait_for("input[name=password]")
            engine.type("input[name=password]", new_password)
            engine.type("input[name=confirmation_password]", new_password)
            engine.click("button[type=submit]")

            return AutomationResult(status=AutomationStatus.SUCCESS, message="Password changed", changed_at=datetime.utcnow())
        except Exception as e:
            return AutomationResult(status=AutomationStatus.NEEDS_MANUAL, message="Flow failed or blocked", error=str(e))
