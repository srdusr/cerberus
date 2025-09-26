"""
Heuristic discovery for password change and reset flows.

This module attempts to dynamically locate "Change password" or "Forgot/Reset password"
paths and, when possible, automatically submit a password rotation using best-effort
selectors. It works with any engine that implements the AutomationEngine Protocol.
"""
from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import List, Optional, Dict, Any, Protocol

from .types import AutomationResult, AutomationStatus
from ..core.models import PasswordEntry

logger = logging.getLogger("cerberus")


DISCOVERY_KEYWORDS = [
    # English
    "change password",
    "password change",
    "update password",
    "reset password",
    "forgot password",
    "forgot your password",
    "security",
    "account settings",
    # Common non-English hints (basic)
    "contraseña", "senha", "mot de passe",
    "passwort", "lozinka", "hasło",
]

# Common input name/id candidates
OLD_PW_CANDIDATES = [
    "current_password",
    "old_password",
    "password_current",
    "passwordOld",
    "password_old",
    "existing_password",
]
NEW_PW_CANDIDATES = [
    "new_password",
    "password_new",
    "password1",
    "password",
    "newPassword",
]
CONFIRM_PW_CANDIDATES = [
    "confirm_password",
    "password_confirm",
    "password2",
    "confirmNewPassword",
]

SUBMIT_CANDIDATES = [
    'button[type="submit"]',
    'input[type="submit"]',
    'button.primary',
    'button.save',
    'button.update',
]


@dataclass
class DiscoveredEndpoint:
    label: str
    href: str


def _js_find_links_script() -> str:
    # Returns JSON array of {text, href}
    return (
        "(() => {"
        " const matches = [];"
        " const anchors = Array.from(document.querySelectorAll('a, button'));"
        " const kws = new Set([" + ",".join([f"'{' '.join(k.split())}'" for k in DISCOVERY_KEYWORDS]) + "]);"
        " for (const el of anchors) {"
        "   const text = (el.textContent || '').trim().toLowerCase();"
        "   const aria = (el.getAttribute('aria-label') || '').trim().toLowerCase();"
        "   const title = (el.getAttribute('title') || '').trim().toLowerCase();"
        "   for (const kw of kws) {"
        "     if (text.includes(kw) || aria.includes(kw) || title.includes(kw)) {"
        "       const href = el.getAttribute('href') || '';"
        "       matches.push({text, href});"
        "       break;"
        "     }"
        "   }"
        " return matches;"
        "})()"
    )


def discover_password_change(engine, base_url: Optional[str]) -> List[DiscoveredEndpoint]:
    """Attempt to discover password change or reset endpoints from a base URL.

    Heuristic approach: scan DOM for anchors/buttons whose text matches discovery keywords.
    """
    try:
        # Ensure we're on the base URL first
        if base_url:
            engine.goto(base_url)
        logger.debug("[discovery] scanning links/buttons for keywords")
    except Exception:
        logger.debug("[discovery] failed to navigate to base URL")
    matches = engine.evaluate(_js_find_links_script())
    endpoints: List[DiscoveredEndpoint] = []
    if isinstance(matches, list):
        for m in matches:
            text = (m.get("text") or "").strip()
            href = (m.get("href") or "").strip()
            if href:
                endpoints.append(DiscoveredEndpoint(text=text, href=href))
    # Deduplicate by href
    unique: Dict[str, DiscoveredEndpoint] = {}
    for e in endpoints:
        unique[e.href] = e
    logger.debug(f"[discovery] found {len(unique)} unique endpoints")
    return list(unique.values())


def _try_type(engine, selector: str, value: str) -> bool:
    try:
        engine.wait_for(selector, timeout_ms=1000)
        engine.type(selector, value)
        logger.debug(f"[discovery] typed into {selector}")
        return True
    except Exception:
        logger.debug(f"[discovery] could not type into {selector}")
        return False


def _try_click(engine, selector: str) -> bool:
    try:
        engine.wait_for(selector, timeout_ms=1000)
        engine.click(selector)
        logger.debug(f"[discovery] clicked {selector}")
        return True
    except Exception:
        logger.debug(f"[discovery] could not click {selector}")
        return False


def _try_login_if_present(engine, entry: PasswordEntry) -> bool:
    """Best-effort login if a login form is present on the current page."""
    try:
        has_form = engine.evaluate(
            "(() => { const p = document.querySelector('form input[type=\\'password\\']'); return !!p; })()"
        )
    except Exception:
        has_form = False
    if not has_form:
        logger.debug("[discovery] no login form present on page")
        return False
    candidates_user = [
        "input[type='email']",
        "input[type='text']",
        "input[name*='user']",
        "input[id*='user']",
        "input[name*='email']",
        "input[id*='email']",
        "input[name*='login']",
        "input[id*='login']",
    ]
    _ = any(_try_type(engine, sel, entry.username) for sel in candidates_user)
    typed_pass = _try_type(engine, "input[type='password']", entry.password)
    submitted = any(_try_click(engine, sel) for sel in SUBMIT_CANDIDATES)
    if not submitted:
        try:
            engine.evaluate("(() => { const p = document.querySelector('input[type=\\'password\\']'); if (p && p.form) { p.form.submit(); return true;} return false; })()")
            submitted = True
        except Exception:
            pass
    ok = typed_pass and submitted
    logger.debug(f"[discovery] login attempt result ok={ok}")
    return ok


def try_submit_password_change(engine, entry: PasswordEntry, new_password: str) -> AutomationResult:
    """Attempt to submit a password change on the current page using common selectors."""
    def candidates(names: List[str]) -> List[str]:
        sels: List[str] = []
        for n in names:
            sels.append(f"input[name='{n}']")
            sels.append(f"input[id='{n}']")
            sels.append(f"input[type='password'][name='{n}']")
            sels.append(f"input[type='password'][id='{n}']")
            sels.append(f"input[placeholder*='{n}']")
            sels.append(f"input[aria-label*='{n}']")
        return sels

    success_old = any(_try_type(engine, sel, entry.password) for sel in candidates(OLD_PW_CANDIDATES))
    success_new = any(_try_type(engine, sel, new_password) for sel in candidates(NEW_PW_CANDIDATES))
    success_confirm = any(_try_type(engine, sel, new_password) for sel in candidates(CONFIRM_PW_CANDIDATES)) or success_new

    submitted = any(_try_click(engine, sel) for sel in SUBMIT_CANDIDATES)
    if not submitted:
        try:
            engine.evaluate("(() => { const el = document.querySelector('input[type=\\'password\\']'); if (el) { el.dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', bubbles: true})); el.form && el.form.submit && el.form.submit(); return true;} return false; })()")
            submitted = True
        except Exception:
            pass

    if (success_new and success_confirm) and (submitted or success_old):
        return AutomationResult(status=AutomationStatus.SUCCESS, message="Submitted change attempt")
    return AutomationResult(status=AutomationStatus.NEEDS_MANUAL, message="Could not auto-submit on page")


def auto_change_flow(engine, entry: PasswordEntry, new_password: str) -> AutomationResult:
    """End-to-end best-effort flow: optional login, discover change endpoint, attempt update."""
    base = entry.url or (("https://" + entry.website) if entry.website and not entry.website.startswith("http") else entry.website) or ""
    if base:
        try:
            logger.debug(f"[discovery] navigating to base URL: {base}")
            engine.goto(base)
            _try_login_if_present(engine, entry)
        except Exception:
            logger.debug("[discovery] failed to navigate or login at base URL")

    endpoints = discover_password_change(engine, base if base else None)
    logger.debug(f"[discovery] candidate endpoints: {len(endpoints)}")

    # Also try common guesses relative to base
    guesses = [
        "/account/security",
        "/settings/security",
        "/settings/password",
        "/profile/security",
        "/user/security",
    ]
    for g in guesses:
        endpoints.append(DiscoveredEndpoint(label=f"guess:{g}", href=(base + g) if base else g))

    for ep in endpoints:
        try:
            target = ep.href
            if not target.startswith("http") and base:
                target = base + ep.href
            if not target:
                continue
            logger.debug(f"[discovery] trying endpoint: {target}")
            engine.goto(target)
            res = try_submit_password_change(engine, entry, new_password)
            if res.status == AutomationStatus.SUCCESS:
                return res
        except Exception:
            logger.debug("[discovery] endpoint attempt failed, trying next")
            continue

    return AutomationResult(status=AutomationStatus.NEEDS_MANUAL, message="No automated flow succeeded")
