from typing import Optional, Dict, Any
from datetime import datetime

from ...core.models import PasswordEntry
from ..types import AutomationResult, AutomationStatus
from .base_site import SiteFlow


class MicrosoftFlow(SiteFlow):
    def match(self, entry: PasswordEntry) -> bool:
        target = (entry.url or entry.website or "").lower()
        return "microsoft.com" in target or "live.com" in target or "office.com" in target

    def perform_change(self, engine, entry: PasswordEntry, new_password: str, options: Optional[Dict[str, Any]] = None) -> AutomationResult:
        try:
            # Login page
            engine.goto("https://login.live.com/")
            engine.wait_for("input[type=email], input[name=loginfmt]")
            engine.type("input[type=email], input[name=loginfmt]", entry.username)
            engine.click("input[type=submit], button[type=submit]")

            # Password step
            try:
                engine.wait_for("input[type=password]", timeout_ms=8000)
            except Exception:
                return AutomationResult(status=AutomationStatus.NEEDS_MFA, message="MFA or challenge present")
            engine.type("input[type=password]", entry.password)
            engine.click("input[type=submit], button[type=submit]")

            # Navigate to security/password change
            engine.goto("https://account.live.com/password/change")
            engine.wait_for("input[name=OldPassword], input[name=CurrentPassword]")
            engine.type("input[name=OldPassword], input[name=CurrentPassword]", entry.password)
            engine.type("input[name=NewPassword], input[name=NewPasswordBox]", new_password)
            engine.type("input[name=ConfirmPassword], input[name=ConfirmNewPasswordBox]", new_password)
            engine.click("button[type=submit], input[type=submit]")

            return AutomationResult(status=AutomationStatus.SUCCESS, message="Password changed", changed_at=datetime.utcnow())
        except Exception as e:
            return AutomationResult(status=AutomationStatus.NEEDS_MANUAL, message="Flow failed or blocked", error=str(e))
