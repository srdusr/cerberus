from typing import Optional, Dict, Any

from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext


class PlaywrightEngine:
    def __init__(self):
        self._pw = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None

    def start(self, headless: bool = True, user_data_dir: Optional[str] = None) -> None:
        self._pw = sync_playwright().start()
        launch_args = {"headless": headless}
        if user_data_dir:
            self._context = self._pw.chromium.launch_persistent_context(user_data_dir, **launch_args)
            pages = self._context.pages
            self._page = pages[0] if pages else self._context.new_page()
        else:
            self._browser = self._pw.chromium.launch(**launch_args)
            self._context = self._browser.new_context()
            self._page = self._context.new_page()

    def stop(self) -> None:
        if self._context:
            self._context.close()
        if self._browser:
            self._browser.close()
        if self._pw:
            self._pw.stop()
        self._page = None
        self._context = None
        self._browser = None
        self._pw = None

    def goto(self, url: str, wait_until: str = "networkidle") -> None:
        assert self._page is not None
        self._page.goto(url, wait_until=wait_until)

    def type(self, selector: str, value: str, clear: bool = True) -> None:
        assert self._page is not None
        locator = self._page.locator(selector)
        if clear:
            locator.fill("")
        locator.type(value)

    def click(self, selector: str) -> None:
        assert self._page is not None
        self._page.click(selector)

    def wait_for(self, selector: str, timeout_ms: int = 15000) -> None:
        assert self._page is not None
        self._page.wait_for_selector(selector, timeout=timeout_ms)

    def evaluate(self, script: str, arg: Optional[Dict[str, Any]] = None) -> Any:
        assert self._page is not None
        return self._page.evaluate(script, arg)


