from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any
from datetime import datetime


class AutomationStatus(str, Enum):
    SUCCESS = "success"
    NEEDS_MFA = "needs_mfa"
    NEEDS_MANUAL = "needs_manual"
    FAILED = "failed"


@dataclass
class AutomationResult:
    status: AutomationStatus
    message: str = ""
    changed_at: Optional[datetime] = None
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


