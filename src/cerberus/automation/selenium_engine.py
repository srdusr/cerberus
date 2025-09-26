from typing import Optional, Dict, Any

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    SELENIUM_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    SELENIUM_AVAILABLE = False


class SeleniumEngine:
    def __init__(self):
        if not SELENIUM_AVAILABLE:
            raise RuntimeError("Selenium is not installed. Install with: pip install selenium")
        self._driver: Optional[webdriver.Chrome] = None

    def start(self, headless: bool = True, user_data_dir: Optional[str] = None) -> None:
        options = ChromeOptions()
        if headless:
            options.add_argument("--headless=new")
        if user_data_dir:
            options.add_argument(f"--user-data-dir={user_data_dir}")
        self._driver = webdriver.Chrome(options=options)

    def stop(self) -> None:
        if self._driver:
            self._driver.quit()
            self._driver = None

    def goto(self, url: str, wait_until: str = "networkidle") -> None:
        assert self._driver is not None
        self._driver.get(url)

    def type(self, selector: str, value: str, clear: bool = True) -> None:
        assert self._driver is not None
        elem = self._driver.find_element(By.CSS_SELECTOR, selector)
        if clear:
            elem.clear()
        elem.send_keys(value)

    def click(self, selector: str) -> None:
        assert self._driver is not None
        elem = self._driver.find_element(By.CSS_SELECTOR, selector)
        elem.click()

    def wait_for(self, selector: str, timeout_ms: int = 15000) -> None:
        assert self._driver is not None
        # Simple polling; users can replace with WebDriverWait if desired
        import time
        end = time.time() + timeout_ms / 1000.0
        while time.time() < end:
            try:
                self._driver.find_element(By.CSS_SELECTOR, selector)
                return
            except Exception:
                time.sleep(0.1)
        raise TimeoutError(f"Timeout waiting for selector: {selector}")

    def evaluate(self, script: str, arg: Optional[Dict[str, Any]] = None) -> Any:
        assert self._driver is not None
        return self._driver.execute_script(script, arg)


