from typing import Optional, Dict, Any
from datetime import datetime

from ...core.models import PasswordEntry
from ..types import AutomationResult, AutomationStatus
from .base_site import SiteFlow


class FacebookFlow(SiteFlow):
    def match(self, entry: PasswordEntry) -> bool:
        target = (entry.url or entry.website or "").lower()
        return "facebook.com" in target or "fb.com" in target

    def perform_change(self, engine, entry: PasswordEntry, new_password: str, options: Optional[Dict[str, Any]] = None) -> AutomationResult:
        try:
            engine.goto("https://www.facebook.com/login/")
            engine.wait_for("input[name=email]")
            engine.type("input[name=email]", entry.username)
            engine.type("input[name=pass]", entry.password)
            engine.click("button[name=login]")

            # Password settings
            engine.goto("https://www.facebook.com/settings?tab=security")
            # New UI is dynamic; try common selectors
            try:
                engine.wait_for("input[type=password]", timeout_ms=8000)
            except Exception:
                return AutomationResult(status=AutomationStatus.NEEDS_MANUAL, message="Security page requires interaction or MFA")

            # Attempt common current/new/confirm fields
            try:
                engine.type("input[name='current_password']", entry.password)
            except Exception:
                pass
            for sel in ["input[name='new_password']", "input[name='password_new']", "input[name='new']"]:
                try:
                    engine.type(sel, new_password)
                    break
                except Exception:
                    continue
            for sel in ["input[name='confirm_password']", "input[name='password_confirm']", "input[name='confirm']"]:
                try:
                    engine.type(sel, new_password)
                    break
                except Exception:
                    continue
            for sel in ["button[type=submit]", "[data-testid='sec_settings_save']", "button"]:
                try:
                    engine.click(sel)
                    break
                except Exception:
                    continue

            return AutomationResult(status=AutomationStatus.SUCCESS, message="Password change attempted", changed_at=datetime.utcnow())
        except Exception as e:
            return AutomationResult(status=AutomationStatus.NEEDS_MANUAL, message="Flow failed or blocked", error=str(e))
