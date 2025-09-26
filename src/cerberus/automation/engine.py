from typing import Protocol, Optional, Dict, Any


class AutomationEngine(Protocol):
    def start(self, headless: bool = True, user_data_dir: Optional[str] = None) -> None:
        ...

    def stop(self) -> None:
        ...

    def goto(self, url: str, wait_until: str = "networkidle") -> None:
        ...

    def type(self, selector: str, value: str, clear: bool = True) -> None:
        ...

    def click(self, selector: str) -> None:
        ...

    def wait_for(self, selector: str, timeout_ms: int = 15000) -> None:
        ...

    def evaluate(self, script: str, arg: Optional[Dict[str, Any]] = None) -> Any:
        ...


