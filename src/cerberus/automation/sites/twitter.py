from typing import Optional, Dict, Any
from datetime import datetime

from ...core.models import PasswordEntry
from ..types import AutomationResult, AutomationStatus
from .base_site import SiteFlow


class TwitterFlow(SiteFlow):
    def match(self, entry: PasswordEntry) -> bool:
        target = (entry.url or entry.website or "").lower()
        return "twitter.com" in target or "x.com" in target

    def perform_change(self, engine, entry: PasswordEntry, new_password: str, options: Optional[Dict[str, Any]] = None) -> AutomationResult:
        try:
            # Login flow
            engine.goto("https://twitter.com/i/flow/login")
            engine.wait_for("input[name='text']")
            engine.type("input[name='text']", entry.username)
            engine.click("div[role='button'][data-testid='LoginForm_Login_Button'], div[role='button']")
            try:
                engine.wait_for("input[name='password']", timeout_ms=8000)
            except Exception:
                return AutomationResult(status=AutomationStatus.NEEDS_MFA, message="MFA or challenge present")
            engine.type("input[name='password']", entry.password)
            engine.click("div[role='button'][data-testid='LoginForm_Login_Button']")

            # Settings (paths change often; best-effort direct link)
            engine.goto("https://twitter.com/settings/password")
            engine.wait_for("input[name='current_password'], input[type='password']")
            # Try to fill typical current/new/confirm fields
            try:
                engine.type("input[name='current_password']", entry.password)
            except Exception:
                pass
            engine.type("input[name='new_password']", new_password)
            engine.type("input[name='password_confirmation']", new_password)
            engine.click("div[role='button'], button[type='submit']")

            return AutomationResult(status=AutomationStatus.SUCCESS, message="Password changed", changed_at=datetime.utcnow())
        except Exception as e:
            return AutomationResult(status=AutomationStatus.NEEDS_MANUAL, message="Flow failed or blocked", error=str(e))
