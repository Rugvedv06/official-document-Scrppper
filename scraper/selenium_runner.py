"""Selenium engine: drives a real Chrome via WebDriver + Chrome DevTools Protocol.

It deliberately reuses the existing capture pipeline rather than duplicating it:
`SeleniumEngine` subclasses `CaptureSession`, so view windows, diagnostics,
JSON handling, the in-page AES decryption, dedup, criteria merging, metadata
rows and post-save validation all work exactly as they do under Playwright.
Only the transport (network events, page handle) is different.
"""

import asyncio
import base64
import json
import threading
import time
import urllib.request
from pathlib import Path

from . import config, diagnostics, storage
from .capture import CaptureSession
from .logger import get_logger

logger = get_logger()

A4_INCHES = (8.27, 11.69)
MARGIN_INCHES = 0.4


class CdpEventTap:
    """Receives Chrome DevTools network events for every page target.

    Selenium 4 removed `WebDriver.add_cdp_listener`, so the events are read
    from Chrome's own DevTools socket instead.  Only events travel over this
    connection; commands (getResponseBody, printToPDF, captureScreenshot)
    still go through `driver.execute_cdp_cmd`.
    """

    POLL_SECONDS = 1.0

    def __init__(self, debugger_address, on_event):
        self._address = self._normalize(debugger_address)
        self._on_event = on_event
        self._stop = threading.Event()
        self._state_lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._pending_lock = threading.Lock()
        self._pending = {}
        self._next_id = 1
        self._sockets = {}  # target id -> websocket
        self._threads = []
        self._supervisor = None
        self._last_count = -1

    @staticmethod
    def _normalize(address):
        """`localhost` resolves through IPv6 first on Windows and costs about
        two seconds per DevTools request; the endpoint is IPv4 only."""
        if not isinstance(address, str):
            return address
        if address.startswith("localhost:"):
            return "127.0.0.1:" + address.split(":", 1)[1]
        if address.startswith("ws://localhost:"):
            return "ws://127.0.0.1:" + address.split(":", 2)[2]
        if address.startswith("http://localhost:"):
            return "http://127.0.0.1:" + address.split(":", 2)[2]
        return address

    def call(self, target_id, method, params=None, timeout=30):
        """Run a CDP command on the same connection that enabled Network, so
        results (e.g. `Network.getResponseBody`) are visible to us."""
        with self._state_lock:
            sock = self._sockets.get(target_id)
        if sock is None:
            raise RuntimeError(f"no CDP connection for target {target_id}")
        with self._send_lock:
            with self._pending_lock:
                self._next_id += 1
                request_id = self._next_id
                box = {}
                event = threading.Event()
                self._pending[request_id] = (event, box)
            sock.send(
                json.dumps(
                    {"id": request_id, "method": method, "params": params or {}}
                )
            )
        if not event.wait(timeout):
            with self._pending_lock:
                self._pending.pop(request_id, None)
            raise TimeoutError(f"{method} timed out after {timeout}s")
        if box.get("error"):
            raise RuntimeError(f"{method}: {box['error']}")
        return box.get("result") or {}

    def start(self):
        # Attach before returning so that no request can slip through before
        # `Network.enable` has been sent.
        self._poll_once()
        self._supervisor = threading.Thread(
            target=self._supervise, name="cdp-tap", daemon=True
        )
        self._supervisor.start()

    def stop(self):
        self._stop.set()
        with self._state_lock:
            sockets = list(self._sockets.values())
        for sock in sockets:
            try:
                sock.close()
            except Exception:
                pass

    def _supervise(self):
        while not self._stop.is_set():
            self._poll_once()
            self._stop.wait(self.POLL_SECONDS)

    def _poll_once(self):
        started = time.monotonic()
        try:
            targets = self._list_pages()
        except Exception as exc:
            logger.debug(
                "CDP target listing failed after %.2fs: %s",
                time.monotonic() - started,
                exc,
            )
            targets = []
        for target in targets:
            target_id = target.get("id")
            if not target_id:
                continue
            with self._state_lock:
                already = target_id in self._sockets
            if already:
                continue
            self._connect(target_id, target.get("webSocketDebuggerUrl"))
        if targets and len(self._sockets) != self._last_count:
            self._last_count = len(self._sockets)
            logger.debug(
                "CDP target poll: %d page(s), %d connected (%.2fs)",
                len(targets),
                len(self._sockets),
                time.monotonic() - started,
            )

    def _list_pages(self):
        url = f"http://{self._address}/json/list"
        with urllib.request.urlopen(url, timeout=5) as response:
            payload = json.load(response)
        return [
            {
                "id": item.get("id"),
                "webSocketDebuggerUrl": self._normalize(
                    item.get("webSocketDebuggerUrl")
                ),
            }
            for item in payload
            if item.get("type") == "page" and item.get("webSocketDebuggerUrl")
        ]

    def _connect(self, target_id, ws_url):
        attach_started = time.monotonic()
        import websocket

        try:
            sock = websocket.create_connection(ws_url, suppress_origin=True, timeout=15)
        except Exception as exc:
            logger.debug("CDP socket connect failed for %s: %s", target_id, exc)
            return
        try:
            sock.send(json.dumps({"id": -1, "method": "Network.enable"}))
            sock.send(json.dumps({"id": -2, "method": "Page.enable"}))
        except Exception as exc:
            logger.debug("CDP enable failed on %s: %s", target_id, exc)
            try:
                sock.close()
            except Exception:
                pass
            return
        with self._state_lock:
            if self._stop.is_set():
                try:
                    sock.close()
                except Exception:
                    pass
                return
            self._sockets[target_id] = sock
        thread = threading.Thread(
            target=self._read,
            args=(target_id, sock),
            name=f"cdp-{target_id[:8]}",
            daemon=True,
        )
        thread.start()
        self._threads.append(thread)
        logger.debug(
            "CDP event tap attached to target %s (%.2fs)",
            target_id,
            time.monotonic() - attach_started,
        )

    def _read(self, target_id, sock):
        try:
            while not self._stop.is_set():
                raw = sock.recv()
                if not raw:
                    continue
                try:
                    message = json.loads(raw)
                except Exception:
                    continue
                method = message.get("method")
                if method is None:
                    if "id" in message:
                        self._resolve(message)
                    continue
                try:
                    self._on_event(method, message.get("params") or {}, target_id)
                except Exception:
                    logger.exception("Error handling CDP event %s", method)
        except Exception as exc:
            if not self._stop.is_set():
                logger.debug("CDP event stream ended for %s: %s", target_id, exc)
        finally:
            with self._state_lock:
                self._sockets.pop(target_id, None)
            try:
                sock.close()
            except Exception:
                pass

    def _resolve(self, message):
        with self._pending_lock:
            pending = self._pending.pop(message.get("id"), None)
        if pending is None:
            return
        event, box = pending
        box["result"] = message.get("result")
        box["error"] = message.get("error")
        event.set()


class _Headers(dict):
    """Case-insensitive header mapping (CDP header names keep their casing)."""

    def __init__(self, mapping=None):
        super().__init__()
        for key, value in (mapping or {}).items():
            self[str(key).lower()] = value

    def get(self, key, default=None):
        return dict.get(self, str(key).lower(), default)


class _CdpRequest:
    def __init__(self, method="GET", url="", post_data=None, headers=None, failure=None):
        self.method = method or "GET"
        self.url = url or ""
        self.post_data = post_data or None
        self.headers = _Headers(headers)
        self.failure = failure

    @property
    def post_data_json(self):
        text = self.post_data or ""
        if not text:
            raise ValueError("no post data")
        try:
            value = json.loads(text)
        except Exception as exc:
            raise ValueError("post data is not JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("post data is not a JSON object")
        return value


class _CdpResponse:
    def __init__(self, url, status, headers, request, body):
        self.url = url
        self.status = status
        self.headers = headers
        self.request = request
        self._body = body

    async def body(self):
        if self._body is None:
            raise RuntimeError("CDP body unavailable")
        return self._body


class _CdpDownload:
    def __init__(self, url, suggested, path):
        self.url = url
        self.suggested_filename = suggested or ""
        self._path = str(path)

    async def path(self):
        return self._path


class _FakeContext:
    """Stands in for a Playwright BrowserContext; only `.pages` is used."""

    def __init__(self, pages):
        self.pages = list(pages)

    def on(self, *_args, **_kwargs):
        return None


class SeleniumPage:
    """Duck-typed page exposing the async API the capture pipeline expects."""

    def __init__(self, engine):
        self._engine = engine

    @property
    def url(self):
        try:
            return self._engine.driver.current_url or ""
        except Exception:
            return ""

    def is_closed(self):
        return False

    async def evaluate(self, script, arg=None):
        return await asyncio.to_thread(self._engine.evaluate_js, script, arg)

    async def wait_for_load_state(self, state="load", timeout=0):
        await asyncio.to_thread(
            self._engine.wait_ready, float(timeout or config.SELENIUM_PAGE_LOAD_TIMEOUT)
        )

    async def pdf(self, **_kwargs):
        return await asyncio.to_thread(self._engine.render_pdf)

    async def screenshot(self, full_page=True, type="png", **_kwargs):
        return await asyncio.to_thread(self._engine.render_screenshot, full_page, type)


class SeleniumEngine(CaptureSession):
    """Playwright-independent capture session backed by WebDriver + CDP."""

    def __init__(self, driver, known_hashes, delay_seconds=0.0):
        self.driver = driver
        self._page = SeleniumPage(self)
        super().__init__(_FakeContext([self._page]), known_hashes, delay_seconds)
        self._loop = None
        self._cmd_lock = threading.Lock()
        self._cdp_requests = {}
        self._cdp_responses = {}
        self._downloads = {}
        self._tap = None

    # ------------------------------------------------------------------
    # command plumbing (ChromeDriver is not safe for concurrent commands)
    # ------------------------------------------------------------------
    def _cdp(self, command, params=None):
        with self._cmd_lock:
            return self.driver.execute_cdp_cmd(command, params or {})

    def _script(self, script, *args, async_=False):
        with self._cmd_lock:
            if async_:
                return self.driver.execute_async_script(script, *args)
            return self.driver.execute_script(script, *args)

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def attach_all(self):
        self._loop = asyncio.get_running_loop()
        try:
            self._cdp(
                "Page.setDownloadBehavior",
                {"behavior": "allow", "downloadPath": str(config.SELENIUM_DOWNLOAD_DIR)},
            )
        except Exception as exc:
            logger.debug("Page.setDownloadBehavior not accepted: %s", exc)
        try:
            self._cdp(
                "Browser.setDownloadBehavior",
                {
                    "behavior": "allow",
                    "downloadPath": str(config.SELENIUM_DOWNLOAD_DIR),
                    "eventsEnabled": True,
                },
            )
        except Exception as exc:
            logger.debug("Browser.setDownloadBehavior not accepted: %s", exc)

        debugger = (
            (self.driver.capabilities or {}).get("goog:chromeOptions") or {}
        ).get("debuggerAddress")
        if not debugger:
            raise RuntimeError(
                "Chrome debuggerAddress is missing from the capabilities; "
                "cannot attach the CDP event tap."
            )
        self._tap = CdpEventTap(debugger, self._dispatch_event)
        self._tap.start()
        diagnostics.header("SELENIUM SESSION START (CDP event tap active)")
        logger.debug("Selenium CDP event tap started on %s", debugger)

    def shutdown(self):
        super().shutdown()
        if self._tap is not None:
            self._tap.stop()
            self._tap = None

    def quit(self):
        with self._cmd_lock:
            try:
                self.driver.quit()
            except Exception:
                pass

    def _dispatch_event(self, method, params, target_id):
        handler = _CDP_EVENT_HANDLERS.get(method)
        if handler is not None:
            handler(self, params, target_id)

    # ------------------------------------------------------------------
    # CDP event handlers (run on ChromeDriver's thread -> hop to the loop)
    # ------------------------------------------------------------------
    def _schedule(self, coro):
        loop = self._loop
        if loop is None or loop.is_closed():
            coro.close()
            return
        try:
            asyncio.run_coroutine_threadsafe(coro, loop)
        except RuntimeError:
            coro.close()

    def _on_request(self, params, target_id=None):
        request = params.get("request") or {}
        self._cdp_requests[params.get("requestId")] = {
            "method": request.get("method") or "GET",
            "url": request.get("url") or "",
            "post_data": request.get("postData"),
            "headers": request.get("headers") or {},
            "target_id": target_id,
        }

    def _on_response(self, params, target_id=None):
        response = params.get("response") or {}
        self._cdp_responses[params.get("requestId")] = {
            "url": response.get("url") or "",
            "status": response.get("status") or 0,
            "headers": response.get("headers") or {},
            "target_id": target_id,
        }

    def _on_finished(self, params, target_id=None):
        self._schedule(self._handle_finished(params.get("requestId"), target_id))

    def _on_failed(self, params, target_id=None):
        request_id = params.get("requestId")
        meta = self._cdp_responses.pop(request_id, None)
        request_meta = self._cdp_requests.pop(request_id, None) or {}
        url = (meta or {}).get("url") or request_meta.get("url") or "<unknown>"
        failure = params.get("errorText") or "unknown"
        request = _CdpRequest(
            request_meta.get("method", "GET"),
            url,
            request_meta.get("post_data"),
            request_meta.get("headers"),
            failure=failure,
        )
        self._schedule(self.handle_request_failed(request))

    def _on_download_begin(self, params, target_id=None):
        self._downloads[params.get("guid")] = {
            "url": params.get("url") or "",
            "suggested": params.get("suggestedFilename") or "",
        }

    def _on_download_progress(self, params, target_id=None):
        if params.get("state") != "completed":
            return
        guid = params.get("guid")
        info = self._downloads.pop(guid, None)
        if not info:
            return
        self._schedule(self._handle_download(info, guid))

    async def _handle_finished(self, request_id, target_id=None):
        response_meta = self._cdp_responses.pop(request_id, None)
        request_meta = self._cdp_requests.pop(request_id, None) or {}
        if response_meta is None:
            return
        target_id = target_id or response_meta.get("target_id")
        body = await asyncio.to_thread(self._read_body, request_id, target_id)
        request = _CdpRequest(
            request_meta.get("method", "GET"),
            response_meta.get("url") or request_meta.get("url", ""),
            request_meta.get("post_data"),
            request_meta.get("headers"),
        )
        response = _CdpResponse(
            response_meta.get("url") or request.url,
            response_meta.get("status") or 0,
            _Headers(response_meta.get("headers")),
            request,
            body,
        )
        try:
            await self.handle_response(response)
        except Exception:
            logger.exception("Error handling CDP response")

    def _read_body(self, request_id, target_id=None):
        tap = self._tap
        if tap is None or not target_id:
            return None
        try:
            payload = tap.call(
                target_id,
                "Network.getResponseBody",
                {"requestId": request_id},
                timeout=15,
            )
        except Exception as exc:
            logger.debug("CDP getResponseBody failed for %s: %s", request_id, exc)
            return None
        text = payload.get("body") or ""
        if payload.get("base64Encoded"):
            try:
                return base64.b64decode(text)
            except Exception:
                return None
        return text.encode("utf-8", "replace")

    async def _handle_download(self, info, guid):
        directory = Path(config.SELENIUM_DOWNLOAD_DIR)
        suggested = info.get("suggested") or ""
        candidate = directory / suggested if suggested else None
        if candidate is None or not candidate.exists():
            files = sorted(
                (p for p in directory.glob("*") if p.is_file()),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            candidate = files[0] if files else None
        if candidate is None or not candidate.exists():
            diagnostics.note(
                f"download completed but the file was not found in "
                f"{directory} (guid={guid})"
            )
            return
        await self.handle_download(_CdpDownload(info.get("url", ""), suggested, candidate))

    # ------------------------------------------------------------------
    # page-side JS (shared snippets from capture.py)
    # ------------------------------------------------------------------
    def evaluate_js(self, script, arg=None):
        js = (script or "").strip()
        if arg is None:
            return self._script(f"return ({js})();")
        wrapper = (
            "var cb = arguments[arguments.length - 1];\n"
            f"Promise.resolve(({js})(arguments[0]))\n"
            "  .then(function (v) { cb(v); },\n"
            "        function (e) { cb({ error: String(e) }); });"
        )
        return self._script(wrapper, arg, async_=True)

    def wait_ready(self, timeout):
        deadline = time.monotonic() + max(1.0, float(timeout))
        while time.monotonic() < deadline:
            try:
                state = self._script("return document.readyState")
            except Exception:
                return
            if state == "complete":
                return
            time.sleep(0.25)

    def render_pdf(self):
        params = {
            "printBackground": True,
            "paperWidth": A4_INCHES[0],
            "paperHeight": A4_INCHES[1],
            "marginTop": MARGIN_INCHES,
            "marginBottom": MARGIN_INCHES,
            "marginLeft": MARGIN_INCHES,
            "marginRight": MARGIN_INCHES,
        }
        payload = self._cdp("Page.printToPDF", params)
        return base64.b64decode(payload["data"])

    def render_screenshot(self, full_page=True, image_format="png"):
        fmt = "jpeg" if str(image_format).lower() in ("jpg", "jpeg") else "png"
        params = {"format": fmt, "fromSurface": True}
        if full_page:
            try:
                metrics = self._cdp("Page.getLayoutMetrics", {})
                size = metrics.get("contentSize") or metrics.get("cssContentSize") or {}
                width, height = size.get("width"), size.get("height")
            except Exception:
                width = height = None
            if width and height:
                params["clip"] = {"x": 0, "y": 0, "width": width, "height": height, "scale": 1}
                params["captureBeyondViewport"] = True
            else:
                params["captureBeyondViewport"] = True
        payload = self._cdp("Page.captureScreenshot", params)
        return base64.b64decode(payload["data"])


_CDP_EVENT_HANDLERS = {
    "Network.requestWillBeSent": SeleniumEngine._on_request,
    "Network.responseReceived": SeleniumEngine._on_response,
    "Network.loadingFinished": SeleniumEngine._on_finished,
    "Network.loadingFailed": SeleniumEngine._on_failed,
    "Page.downloadWillBegin": SeleniumEngine._on_download_begin,
    "Page.downloadProgress": SeleniumEngine._on_download_progress,
    "Browser.downloadWillBegin": SeleniumEngine._on_download_begin,
    "Browser.downloadProgress": SeleniumEngine._on_download_progress,
}


def create_driver(profile_dir=None):
    """Start Chrome with a persistent profile so the login survives restarts."""
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options

    options = Options()
    profile = Path(profile_dir or config.SELENIUM_PROFILE_DIR).resolve()
    profile.mkdir(parents=True, exist_ok=True)
    config.SELENIUM_DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    options.add_argument(f"--user-data-dir={profile}")
    options.add_argument("--disable-notifications")
    options.add_argument("--no-first-run")
    options.add_argument("--no-default-browser-check")
    options.add_argument("--disable-popup-blocking")
    if config.SELENIUM_HEADLESS:
        options.add_argument("--headless=new")
    options.add_experimental_option(
        "prefs",
        {
            "download.default_directory": str(config.SELENIUM_DOWNLOAD_DIR),
            "download.prompt_for_download": False,
            "download.directory_upgrade": True,
            "plugins.always_open_pdf_externally": False,
        },
    )
    driver = webdriver.Chrome(options=options)
    driver.set_page_load_timeout(config.SELENIUM_PAGE_LOAD_TIMEOUT)
    driver.set_script_timeout(config.SELENIUM_SCRIPT_TIMEOUT)
    logger.info("Chrome started (profile=%s)", profile)
    return driver
