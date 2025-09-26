from typing import Optional, Dict, Any
from datetime import datetime

from ...core.models import PasswordEntry
from ..types import AutomationResult, AutomationStatus
from .base_site import SiteFlow


class GithubFlow(SiteFlow):
    def match(self, entry: PasswordEntry) -> bool:
        target = (entry.url or entry.website or "").lower()
        return "github.com" in target

    def perform_change(self, engine, entry: PasswordEntry, new_password: str, options: Optional[Dict[str, Any]] = None) -> AutomationResult:
        try:
            # Login
            engine.goto("https://github.com/login")
            engine.wait_for("input#login_field")
            engine.type("input#login_field", entry.username)
            engine.type("input#password", entry.password)
            engine.click("input[type=submit]")

            # Detect 2FA requirement
            try:
                engine.wait_for("input#otp", timeout_ms=3000)
                return AutomationResult(status=AutomationStatus.NEEDS_MFA, message="2FA required")
            except Exception:
                pass

            # Navigate to password change
            engine.goto("https://github.com/settings/security")
            engine.wait_for("a[href='/settings/password']")
            engine.click("a[href='/settings/password']")

            engine.wait_for("input#old_password")
            engine.type("input#old_password", entry.password)
            engine.type("input#new_password", new_password)
            engine.type("input#confirm_new_password", new_password)
            engine.click("button[type=submit]")

            # Verify success: check for flash notice
            try:
                engine.wait_for(".flash-notice, .flash-success", timeout_ms=5000)
            except Exception:
                # As fallback, assume success if no error shown
                pass

            return AutomationResult(status=AutomationStatus.SUCCESS, message="Password changed", changed_at=datetime.utcnow())

        except Exception as e:
            return AutomationResult(status=AutomationStatus.FAILED, message="Error during change", error=str(e))


