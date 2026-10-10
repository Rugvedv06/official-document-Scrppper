import argparse
import asyncio
import sys
import time

from playwright.async_api import async_playwright

from . import config, storage
from .capture import CaptureSession
from .logger import get_logger, setup_logging

logger = get_logger()

_INSTRUCTIONS = """
==========================================================================
  Maharashtra e-Records: manual document capture
  A Chromium browser has been opened in headed mode.

  Follow these steps:
  1. Log in manually (complete CAPTCHA / OTP if asked).
  2. Perform ONE search manually using the site's own forms.
  3. Click "View" on a land-record row to open the document.
  4. The scraper watches all network traffic. When a real document
     (PDF / image / binary) is downloaded it is saved to:
       data/documents/
     and one row is appended to:
       data/metadata.csv
  5. Repeat: search, click View, repeat. Every new document is captured.
  6. Press Ctrl+C on this console window to stop the scraper.

  Diagnostics are appended to:
    logs/document_network_debug.txt
  It logs METHOD | URL | STATUS | CONTENT-TYPE | SIZE | POST-FIELD NAMES
  only - no cookies, tokens, passwords or auth headers. If a View click
  produces no saved document, the debug file ends with a block listing
  every response seen in that window so you can identify the carrier.

  Duplicates (same SHA-256 hash) are automatically skipped using
  data/downloaded_hashes.txt.

  This tool does NOT automate login, CAPTCHA, OTP, search, or clicks.
  Everything happens through your own manual, legitimate browser session.
==========================================================================
"""


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="erecords-scraper",
        description="Manual document capture from Maharashtra e-Records "
        "(aapleabhilekh.mahabhumi.gov.in/erecords).",
    )
    parser.add_argument(
        "--engine",
        choices=("playwright", "selenium"),
        default="playwright",
        help="Browser engine. 'playwright' (default) drives Chromium through "
        "Playwright; 'selenium' drives your installed Chrome/Edge through "
        "WebDriver + the Chrome DevTools Protocol. Both share the same "
        "capture, decrypt and storage pipeline.",
    )
    parser.add_argument(
        "--profile-dir",
        default=None,
        help="Persistent browser profile directory used to reuse the "
        "authenticated session between runs. Defaults to "
        f"{config.PROFILE_DIR} for --engine playwright and "
        f"{config.SELENIUM_PROFILE_DIR} for --engine selenium.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=config.REQUEST_DELAY_SECONDS,
        help="Seconds to wait before saving each captured document "
        "(politeness/rate-limit guard).",
    )
    parser.add_argument(
        "--max-seconds",
        type=float,
        default=0,
        help="Stop automatically after this many seconds "
        "(0 = run until interrupted).",
    )
    return parser.parse_args(argv)


def _print_instructions(args=None):
    text = _INSTRUCTIONS
    if getattr(args, "engine", "playwright") == "selenium":
        text = text.replace(
            "  A Chromium browser has been opened in headed mode.",
            "  A Chrome browser has been opened in headed mode\n"
            "  (Selenium engine: WebDriver + Chrome DevTools Protocol).",
        )
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


async def run(args):
    setup_logging()
    storage.ensure_dirs()
    storage.init_metadata_csv()
    known_hashes = storage.load_hashes()
    logger.info("Initialised. Known hashes loaded: %d", len(known_hashes))

    if args.engine == "selenium":
        await _run_selenium(args, known_hashes)
    else:
        await _run_playwright(args, known_hashes)
    logger.info("Scraper session finished.")


async def _run_playwright(args, known_hashes):
    profile_dir = args.profile_dir or str(config.PROFILE_DIR)
    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            profile_dir,
            headless=False,
            no_viewport=True,
        )
        page = context.pages[0] if context.pages else await context.new_page()
        await page.goto(config.TARGET_URL, wait_until="domcontentloaded")

        session = CaptureSession(context, known_hashes, delay_seconds=args.delay)
        session.attach_all()
        _print_instructions(args)

        started = time.monotonic()
        try:
            while True:
                await asyncio.sleep(0.5)
                if args.max_seconds and (time.monotonic() - started) >= args.max_seconds:
                    logger.info("Reached --max-seconds limit; stopping.")
                    break
                open_pages = [pg for pg in context.pages if not pg.is_closed()]
                if not open_pages:
                    logger.info("All browser windows were closed; stopping.")
                    break
        finally:
            session.shutdown()
            await asyncio.sleep(0)
            await context.close()


async def _run_selenium(args, known_hashes):
    from .selenium_runner import SeleniumEngine, create_driver

    driver = await asyncio.to_thread(create_driver, args.profile_dir)
    session = None
    try:
        await asyncio.to_thread(driver.get, config.TARGET_URL)
        session = SeleniumEngine(driver, known_hashes, delay_seconds=args.delay)
        session.attach_all()
        _print_instructions(args)

        started = time.monotonic()
        while True:
            await asyncio.sleep(0.5)
            if args.max_seconds and (time.monotonic() - started) >= args.max_seconds:
                logger.info("Reached --max-seconds limit; stopping.")
                break
            try:
                await asyncio.to_thread(lambda: driver.current_url)
            except Exception:
                logger.info("Browser window was closed; stopping.")
                break
    finally:
        if session is not None:
            session.shutdown()
            await asyncio.sleep(0)
            await asyncio.to_thread(session.quit)
