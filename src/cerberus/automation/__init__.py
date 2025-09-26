"""Automation layer for password rotation via the web.

This package provides abstractions and engines (Playwright/Selenium) to automate
site-specific password change flows, along with runners and policy helpers.
"""

from .types import AutomationResult, AutomationStatus
from .engine import AutomationEngine
from .runner import RotationRunner, RotationSelector

__all__ = [
    'AutomationEngine',
    'AutomationResult',
    'AutomationStatus',
    'RotationRunner',
    'RotationSelector',
]


