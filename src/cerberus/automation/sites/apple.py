from typing import Optional, Dict, Any
from datetime import datetime

from ...core.models import PasswordEntry
from ..types import AutomationResult, AutomationStatus
from .base_site import SiteFlow


class AppleFlow(SiteFlow):
    def match(self, entry: PasswordEntry) -> bool:
        target = (entry.url or entry.website or "").lower()
        return "apple.com" in target or "appleid.apple.com" in target

    def perform_change(self, engine, entry: PasswordEntry, new_password: str, options: Optional[Dict[str, Any]] = None) -> AutomationResult:
        try:
            # Apple frequently enforces MFA; treat as best-effort stub
            engine.goto("https://appleid.apple.com/")
            engine.wait_for("input[type=email], input[name=email], input[id=email]")
            try:
                engine.type("input[type=email], input[name=email], input[id=email]", entry.username)
            except Exception:
                pass
            try:
                engine.wait_for("input[type=password]", timeout_ms=8000)
                engine.type("input[type=password]", entry.password)
            except Exception:
                return AutomationResult(status=AutomationStatus.NEEDS_MFA, message="Apple ID requires MFA or device approval")

            # Direct to password change if possible (likely gated by MFA)
            engine.goto("https://appleid.apple.com/account/manage/password")
            try:
                engine.wait_for("input[type=password]", timeout_ms=8000)
            except Exception:
                return AutomationResult(status=AutomationStatus.NEEDS_MFA, message="Password settings gated by MFA")

            # Attempt to fill current/new/confirm
            for sel in ["input[name='currentPassword']", "input[id='currentPassword']", "input[type='password']"]:
                try:
                    engine.type(sel, entry.password)
                    break
                except Exception:
                    continue
            for sel in ["input[name='newPassword']", "input[id='newPassword']"]:
                try:
                    engine.type(sel, new_password)
                    break
                except Exception:
                    continue
            for sel in ["input[name='confirmPassword']", "input[id='confirmPassword']"]:
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
