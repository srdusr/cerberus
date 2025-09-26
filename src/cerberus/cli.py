import argparse
from typing import List

from cerberus.core.password_manager import PasswordManager
from cerberus.automation.playwright_engine import PlaywrightEngine
from cerberus.automation.selenium_engine import SeleniumEngine, SELENIUM_AVAILABLE
from cerberus.automation.runner import RotationRunner, RotationSelector
from cerberus.automation.policy import generate_for_entry
from cerberus.automation.sites.github import GithubFlow


def cli():
    parser = argparse.ArgumentParser(prog="cerberus")
    sub = parser.add_subparsers(dest="command")

    rotate = sub.add_parser("rotate", help="Rotate passwords via web automation")
    rotate.add_argument("--engine", choices=["playwright", "selenium"], default="playwright")
    rotate.add_argument("--data-dir", default=None, help="Password manager data dir")
    rotate.add_argument("--master", required=True, help="Master password")
    rotate.add_argument("--all", action="store_true", help="Rotate all entries")
    rotate.add_argument("--compromised", action="store_true", help="Rotate only compromised entries")
    rotate.add_argument("--tag", default=None)
    rotate.add_argument("--domain", default=None)
    rotate.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()

    if args.command == "rotate":
        pm = PasswordManager(data_dir=args.data_dir, master_password=args.master)

        engine = PlaywrightEngine() if args.engine == "playwright" else None
        if args.engine == "selenium":
            if not SELENIUM_AVAILABLE:
                raise SystemExit("Selenium not installed. Install extra: pip install .[automation-selenium]")
            engine = SeleniumEngine()

        engine.start(headless=True)
        try:
            flows = [GithubFlow()]
            runner = RotationRunner(engine, flows, pm)
            selector = RotationSelector(
                all=args.all,
                compromised_only=args.compromised,
                tag=args.tag,
                domain=args.domain,
            )
            results = runner.rotate(selector, lambda e: generate_for_entry(pm, e), dry_run=args.dry_run)
            for r in results:
                print(f"{r.status}: {r.message}")
        finally:
            engine.stop()
    else:
        parser.print_help()
