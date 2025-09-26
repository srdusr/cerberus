from typing import Optional, Dict, Any
from datetime import datetime

from ...core.models import PasswordEntry
from ..types import AutomationResult, AutomationStatus
from .base_site import SiteFlow


class LinkedInFlow(SiteFlow):
    def match(self, entry: PasswordEntry) -> bool:
        target = (entry.url or entry.website or "").lower()
        return "linkedin.com" in target

    def perform_change(self, engine, entry: PasswordEntry, new_password: str, options: Optional[Dict[str, Any]] = None) -> AutomationResult:
        try:
            engine.goto("https://www.linkedin.com/login")
            engine.wait_for("input#username")
            engine.type("input#username", entry.username)
            engine.type("input#password", entry.password)
            engine.click("button[type=submit]")

            engine.goto("https://www.linkedin.com/psettings/change-password")
            try:
                engine.wait_for("input[type=password]", timeout_ms=8000)
            except Exception:
                return AutomationResult(status=AutomationStatus.NEEDS_MANUAL, message="Password settings gated or MFA required")

            # Fill current/new/confirm
            for sel in ["input[name='currentPassword']", "input#current-password", "input[type='password']"]:
                try:
                    engine.type(sel, entry.password)
                    break
                except Exception:
                    continue
            for sel in ["input[name='newPassword']", "input#new-password"]:
                try:
                    engine.type(sel, new_password)
                    break
                except Exception:
                    continue
            for sel in ["input[name='confirmPassword']", "input#confirm-password"]:
                try:
                    engine.type(sel, new_password)
                    break
                except Exception:
                    continue
            for sel in ["button[type=submit]", "button"]:
                try:
                    engine.click(sel)
                    break
                except Exception:
                    continue

            return AutomationResult(status=AutomationStatus.SUCCESS, message="Password change attempted", changed_at=datetime.utcnow())
        except Exception as e:
            return AutomationResult(status=AutomationStatus.NEEDS_MANUAL, message="Flow failed or blocked", error=str(e))
