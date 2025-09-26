from typing import Dict

from ..core.password_manager import PasswordManager
from ..core.models import PasswordEntry


SITE_POLICY: Dict[str, Dict] = {
    # domain_substring: policy
    "github.com": {"length": 20, "use_upper": True, "use_lower": True, "use_digits": True, "use_special": True},
    "google.com": {"length": 20, "use_upper": True, "use_lower": True, "use_digits": True, "use_special": False},
}


def generate_for_entry(pm: PasswordManager, entry: PasswordEntry) -> str:
    url = entry.url or entry.website or ""
    selected = None
    for key, policy in SITE_POLICY.items():
        if key in url:
            selected = policy
            break
    if not selected:
        selected = {"length": 20, "use_upper": True, "use_lower": True, "use_digits": True, "use_special": True}
    return pm.generate_password(**selected)


