import asyncio
import base64
import datetime as dt
import json
import re
import time
import urllib.parse
from pathlib import Path

from . import config, diagnostics, network, storage
from .logger import get_logger
from .models import DocumentRecord, SearchCriteria

logger = get_logger()

_FORM_SNAPSHOT_JS = """
() => {
  const out = [];
  const els = document.querySelectorAll('input, select, textarea');
  for (const el of els) {
    const type = (el.type || '').toLowerCase();
    const id = el.id || '';
    const name = el.name || '';
    if (type === 'password') continue;
    if (id.startsWith('__') || name.startsWith('__')) continue;
    const blocked = /token|otp|password|passwd|secret|auth|cookie|bearer|session|mobile|phone|email/i;
    if (blocked.test(id) || blocked.test(name)) continue;
    const holder = (el.getAttribute('aria-label') || el.getAttribute('title') || '').trim();
    const ph = (el.getAttribute('placeholder') || '').trim();
    const val = (el.value || '').trim();
    out.push({
      tag: el.tagName.toLowerCase(),
      id: id,
      name: name,
      type: type,
      ph: ph,
      holder: holder,
      val: val.slice(0, 200),
    });
    if (out.length >= 80) break;
  }
  return out;
}
"""

_FOLLOW_FETCH_JS = """
async (url) => {
  try {
    const res = await fetch(url, { credentials: 'same-origin' });
    const buf = new Uint8Array(await res.arrayBuffer());
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < buf.length; i += chunk) {
      binary += String.fromCharCode.apply(null, buf.subarray(i, i + chunk));
    }
    return {
      ok: res.ok,
      status: res.status,
      contentType: res.headers.get('content-type') || '',
      b64: btoa(binary),
    };
  } catch (err) {
    return { error: String(err) };
  }
}
"""

_DECRYPT_JS = """
async (input) => {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    return { error: 'WebCrypto unavailable (page is not a secure context)' };
  }
  const b64decode = (s) => {
    const clean = String(s).replace(/\\s+/g, '');
    const bin = atob(clean);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  };
  const b64encode = (u8) => {
    let bin = '';
    const chunk = 0x8000;
    for (let i = 0; i < u8.length; i += chunk) {
      bin += String.fromCharCode.apply(null, u8.subarray(i, i + chunk));
    }
    return btoa(bin);
  };
  const buf = (u8) => u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);

  const MAGIC = [
    { sig: [0x25, 0x50, 0x44, 0x46, 0x2d], mime: 'application/pdf', ext: 'pdf', deep: true },
    { sig: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], mime: 'image/png', ext: 'png' },
    { sig: [0xff, 0xd8, 0xff], mime: 'image/jpeg', ext: 'jpg' },
    { sig: [0x47, 0x49, 0x46, 0x38], mime: 'image/gif', ext: 'gif' },
    { sig: [0x49, 0x49, 0x2a, 0x00], mime: 'image/tiff', ext: 'tif' },
    { sig: [0x4d, 0x4d, 0x00, 0x2a], mime: 'image/tiff', ext: 'tif' },
    { sig: [0x42, 0x4d], mime: 'image/bmp', ext: 'bmp' },
    { sig: [0x50, 0x4b, 0x03, 0x04], mime: 'application/zip', ext: 'zip' },
  ];
  const sniff = (u8) => {
    for (const m of MAGIC) {
      const window = m.deep ? Math.min(u8.length, 1024) : Math.min(u8.length, 32);
      outer:
      for (let i = 0; i + m.sig.length <= window; i++) {
        for (let j = 0; j < m.sig.length; j++) {
          if (u8[i + j] !== m.sig[j]) continue outer;
        }
        return m;
      }
    }
    return null;
  };
  const preview = (u8) => {
    let hex = '';
    const text = [];
    const n = Math.min(u8.length, 24);
    for (let i = 0; i < n; i++) {
      hex += (i ? ' ' : '') + u8[i].toString(16).padStart(2, '0');
      text.push(u8[i] >= 32 && u8[i] < 127 ? String.fromCharCode(u8[i]) : '.');
    }
    return hex + ' |' + text.join('') + '|';
  };

  let keyBytes, ivBytes, dataBytes;
  try { keyBytes = b64decode(input.keyB64); }
  catch (e) { return { error: 'key decode: ' + e }; }
  try { ivBytes = b64decode(input.ivB64 || ''); }
  catch (e) { return { error: 'iv decode: ' + e }; }
  try { dataBytes = b64decode(input.dataB64); }
  catch (e) { return { error: 'data decode: ' + e }; }

  const ivCandidates = [];
  const pushIv = (label, bytes) => {
    if (bytes && bytes.length && !ivCandidates.some((c) => c.label === label)) {
      ivCandidates.push({ label: label, bytes: bytes });
    }
  };
  pushIv('as-is(' + ivBytes.length + ')', ivBytes);
  if (ivBytes.length !== 12) pushIv('first12', ivBytes.slice(0, 12));
  if (ivBytes.length !== 16) pushIv('first16', ivBytes.slice(0, 16));
  if (!ivBytes.length) pushIv('zero16', new Uint8Array(16));

  const attempts = [];
  const successes = [];

  for (const ivc of ivCandidates) {
    let key;
    try {
      key = await crypto.subtle.importKey('raw', buf(keyBytes), 'AES-CBC',
        false, ['decrypt']);
    } catch (e) {
      attempts.push('import(' + ivc.label + '): ' + e);
      break;
    }

    // 1. AES-GCM, authentication tag appended to the ciphertext
    if (dataBytes.length > 16) {
      const ct = dataBytes.slice(0, dataBytes.length - 16);
      const tag = dataBytes.slice(dataBytes.length - 16);
      const combined = new Uint8Array(ct.length + tag.length);
      combined.set(ct, 0);
      combined.set(tag, ct.length);
      let gcmKey;
      try {
        gcmKey = await crypto.subtle.importKey('raw', buf(keyBytes), 'AES-GCM',
          false, ['decrypt']);
        const pt = new Uint8Array(await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: buf(ivc.bytes), tagLength: 128 },
          gcmKey, buf(combined)));
        successes.push({ alg: 'AES-GCM/' + ivc.label, bytes: pt });
        attempts.push('AES-GCM/' + ivc.label + ': ok ' + pt.length);
      } catch (e) {
        attempts.push('AES-GCM/' + ivc.label + ': ' + e);
      }
    }

    // 2. AES-CBC (WebCrypto enforces PKCS#7 padding)
    if (ivc.bytes.length === 16) {
      try {
        const pt = new Uint8Array(await crypto.subtle.decrypt(
          { name: 'AES-CBC', iv: buf(ivc.bytes) }, key, buf(dataBytes)));
        successes.push({ alg: 'AES-CBC/' + ivc.label, bytes: pt });
        attempts.push('AES-CBC/' + ivc.label + ': ok ' + pt.length);
      } catch (e) {
        attempts.push('AES-CBC/' + ivc.label + ': ' + e);
      }

      // 3. AES-CTR
      try {
        const ctrKey = await crypto.subtle.importKey('raw', buf(keyBytes),
          'AES-CTR', false, ['decrypt']);
        const pt = new Uint8Array(await crypto.subtle.decrypt(
          { name: 'AES-CTR', counter: buf(ivc.bytes), length: 64 },
          ctrKey, buf(dataBytes)));
        successes.push({ alg: 'AES-CTR/' + ivc.label, bytes: pt });
        attempts.push('AES-CTR/' + ivc.label + ': ok ' + pt.length);
      } catch (e) {
        attempts.push('AES-CTR/' + ivc.label + ': ' + e);
      }
    }
  }

  for (const s of successes) {
    const found = sniff(s.bytes);
    if (found) {
      return {
        ok: true, alg: s.alg, mime: found.mime, ext: found.ext,
        size: s.bytes.length, b64: b64encode(s.bytes), attempts: attempts,
      };
    }
  }
  return {
    error: 'no algorithm produced a document',
    attempts: attempts,
    preview: successes.length ? preview(successes[0].bytes) : null,
    successAlgs: successes.map((s) => s.alg + ':' + s.bytes.length),
  };
}
"""

_CRITERIA_KEY_MAP = {
    "surveyno": "survey_no",
    "survey_no": "survey_no",
    "survey": "survey_no",
    "survey_number": "survey_no",
    "surveynumber": "survey_no",
    "hissano": "hissa_no",
    "hissa_no": "hissa_no",
    "hissa": "hissa_no",
    "hissa_number": "hissa_no",
    "hissanumber": "hissa_no",
    "oldsurveyno": "old_survey_no",
    "old_survey_no": "old_survey_no",
    "oldsurvey": "old_survey_no",
    "old_survey": "old_survey_no",
    "gatno": "gat_no",
    "gat_no": "gat_no",
    "gat": "gat_no",
    "gat_number": "gat_no",
    "gatnumber": "gat_no",
    "fromyear": "from_year",
    "from_year": "from_year",
    "frm_year": "from_year",
    "frmyear": "from_year",
    "toyear": "to_year",
    "to_year": "to_year",
    "upto_year": "to_year",
    "uptoyear": "to_year",
}

_INVALID_FILENAME_CHARS = re.compile(r'[\\/:*?"<>|\s]+')

_EXTENSION_CONTENT_TYPES = {
    "pdf": "application/pdf",
    "jpg": "image/jpeg",
    "png": "image/png",
    "tif": "image/tiff",
    "gif": "image/gif",
    "bmp": "image/bmp",
}

_IMAGE_EXTENSIONS = ("jpg", "png", "tif", "gif", "bmp")


def _sanitize_stem(value):
    stem = re.sub(_INVALID_FILENAME_CHARS, "_", value).strip("._")
    return stem[:80] or None


def _criteria_stem(criteria) -> str:
    parts = []
    if criteria.survey_no:
        parts.append(f"S{criteria.survey_no}")
    if criteria.old_survey_no:
        parts.append(f"OS{criteria.old_survey_no}")
    if criteria.hissa_no:
        parts.append(f"H{criteria.hissa_no}")
    if criteria.gat_no:
        parts.append(f"G{criteria.gat_no}")
    if not parts and criteria.from_year:
        parts.append(f"Y{criteria.from_year}")
    return "_".join(parts)


def _build_saved_name(record_id, safe_stem, extension):
    stem = safe_stem or f"document_{record_id:05d}"
    suffix = f".{extension}"
    if stem.casefold().endswith(suffix):
        stem = stem[: -len(suffix)].rstrip("._") or stem
    return f"{record_id:05d}_{stem}.{extension}"


def _safe_url(resource):
    try:
        return resource.url
    except Exception:
        return "<unavailable>"


def _is_valid_pdf(body: bytes) -> bool:
    return b"%PDF-" in body[:1024]


def _response_status(response):
    """HTTP status of a response, or '' when it is unavailable."""
    try:
        return response.status
    except Exception:
        return ""


_SECRET_IN_TEXT_RE = re.compile(
    r"(?i)\b(token|otp|password|passwd|authorization|cookie|bearer)"
    r"(\s*[=:]\s*)\S+"
)
_JSON_ERROR_KEYS = (
    "exception",
    "error",
    "errormessage",
    "errmsg",
    "message",
    "msg",
    "reason",
    "description",
)
# Only logged when the payload is not an explicit success: these names are
# also used for ordinary "OTP sent" / "record found" confirmations.
_JSON_SOFT_ERROR_KEYS = frozenset({"message", "msg", "reason", "description"})


def _note_json_error(payload, url):
    """Surface the site's own error text.

    These portals report failures inside a normal HTTP 200 JSON body, so
    without this the reason a document refuses to open is invisible.  Values
    are scrubbed for anything that looks like a credential before logging.
    """
    if not isinstance(payload, dict):
        return
    success = payload.get("success")
    lowered = {str(k).casefold(): k for k in payload}
    for key in _JSON_ERROR_KEYS:
        original = lowered.get(key)
        if original is None:
            continue
        if key in _JSON_SOFT_ERROR_KEYS and success is True:
            continue
        value = payload.get(original)
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False)
        if not isinstance(value, str) or not value.strip():
            continue
        text = _SECRET_IN_TEXT_RE.sub(
            lambda m: f"{m.group(1)}{m.group(2)}<redacted>", value.strip()
        )
        text = " ".join(text.split())[:600]
        diagnostics.note(
            f"site reported an error (success={success!r}) on "
            f"{network.redact_url(url)}: {original}={text}"
        )
        return
    if success is False:
        diagnostics.note(
            f"site response has success=False and no error text "
            f"(keys={sorted(str(k) for k in payload)}): "
            f"{network.redact_url(url)}"
        )


def _largest_decode(value: str):
    """Decode an opaque base64/base64url/hex string, preferring the longest
    candidate, or None when nothing decodes."""
    candidates = network.decode_candidates(value)
    if not candidates:
        return None
    return max(candidates, key=lambda item: len(item[1]))[1]


def _looks_like_encoded_blob(value: str) -> bool:
    """True for a single-segment path that is really an encoded payload such
    as '/3KkcQjbxXaj0mu8ryQ0OF6qOTPNiTneQiBgITY0bbY=' rather than a site path."""
    if value.count("/") != 1 or not value.startswith("/"):
        return False
    if len(value) < 24 or len(value) % 4 != 0:
        return False
    if "." in value or "?" in value or "#" in value:
        return False
    return re.fullmatch(r"[A-Za-z0-9+/=_-]+", value) is not None


class CaptureSession:
    def __init__(self, context, known_hashes, delay_seconds=0.0):
        self.context = context
        self.known_hashes = known_hashes
        self.delay_seconds = delay_seconds
        self.next_id = storage.next_id()
        self.view_window_until = 0.0
        self.view_window_saved = False
        self.view_window_source = None
        self.view_window_events = []
        self.range_buffers = {}
        self.pending_criteria = {}
        self.followed_urls = set()
        self.followup_budget = 0
        self._tasks = set()
        self.pending_cipher_b64 = None
        self.pending_cipher_url = None
        self.pending_cipher_hint = None
        self.pending_key = None
        self.pending_iv = None
        self.pending_key_url = None
        self.render_fallback_seen = set()
        self.render_hint_urls = set()

    def attach_all(self):
        self.context.on("response", self._guard(self.handle_response))
        self.context.on("requestfailed", self._guard(self.handle_request_failed))
        self.context.on("download", self._guard(self.handle_download))
        self.context.on(
            "page",
            lambda page: logger.debug("New page/tab opened: %s", _safe_url(page)),
        )
        diagnostics.header("SESSION START (context-level listeners active)")
        logger.debug("Listening for responses across all pages in the context.")

    def shutdown(self):
        for task in list(self._tasks):
            task.cancel()
        self._tasks.clear()

    def _guard(self, handler):
        async def wrapper(payload):
            try:
                await handler(payload)
            except Exception:
                logger.exception(
                    "Error handling %s", type(payload).__name__
                )

        return wrapper

    def _in_view_window(self) -> bool:
        return time.monotonic() < self.view_window_until

    def _open_view_window(self, source: str):
        now = time.monotonic()
        is_new = now > self.view_window_until
        if is_new:
            self.view_window_events = []
            self.view_window_saved = False
            self.view_window_source = source
            self.followup_budget = 3
            diagnostics.header(f"VIEW WINDOW OPENED (trigger: {source})")
            task = asyncio.ensure_future(self._window_watchdog())
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        self.view_window_until = now + config.VIEW_WINDOW_SECONDS
        return is_new

    async def _window_watchdog(self):
        while True:
            await asyncio.sleep(1.0)
            if time.monotonic() >= self.view_window_until:
                break
        if self.view_window_saved:
            diagnostics.note("VIEW WINDOW CLOSED - document captured.")
            return
        lines = [
            "VIEW WINDOW CLOSED - NO DOCUMENT WAS SAVED.",
            f"Trigger: {self.view_window_source}",
            f"Browser is currently on: {self._current_page_url()}",
            "",
            "Requests/responses observed during this window "
            "(METHOD | URL | STATUS | CONTENT-TYPE | SIZE):",
        ]
        lines.extend(f"  {entry}" for entry in self.view_window_events)
        lines.append("")
        lines.append(
            "Inspect these responses to find which one carries the document bytes."
        )
        page_url = self._current_page_url().casefold()
        if page_url.rstrip("/").endswith("/erecords") or "login" in page_url:
            lines.append(
                "The browser is back on the portal's landing/login page, so the "
                "session has expired - log in again before clicking View."
            )
        elif config.RENDER_ON_EMPTY_VIEW_WINDOW:
            lines.append(
                "No document bytes arrived, so the current page will be "
                "rendered and saved instead (see the RENDER exchange below)."
            )
        diagnostics.write_block(lines)
        logger.warning(
            "View flow completed but no document was saved (%d responses in window). "
            "See logs/document_network_debug.txt",
            len(self.view_window_events),
        )
        if config.RENDER_ON_EMPTY_VIEW_WINDOW and not self._login_page_shown():
            task = asyncio.ensure_future(self._render_view_window_page())
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    def _login_page_shown(self) -> bool:
        page_url = self._current_page_url().casefold()
        return page_url.rstrip("/").endswith("/erecords") or "login" in page_url

    async def _render_view_window_page(self):
        """Save what the browser is showing when no document was transmitted."""
        source = self._current_page_url()
        digest = network.sha256_hex(
            f"view-window-render\n{source}".encode("utf-8", "replace")
        )
        return await self._render_fallback(source, "", b"", digest)

    def _current_page_url(self) -> str:
        page = self._open_page()
        if page is None:
            return "(no open page)"
        try:
            return page.url or "(about:blank)"
        except Exception:
            return "(unknown)"

    async def handle_request_failed(self, request):
        url = _safe_url(request)
        try:
            failure = request.failure or "unknown"
        except Exception:
            failure = "unknown"
        method = getattr(request, "method", "?")
        line = diagnostics.exchange(
            method, url, "failed", "", None, [], f"failure={failure}"
        )
        if self._in_view_window():
            self.view_window_events.append(line)
        if network.is_view_flow(request, url):
            diagnostics.note(
                f"the site aborted the document request ({failure}) - the "
                f"browser session was probably lost or the page navigated away "
                f"mid-request; log in again and retry"
            )
            logger.warning("View request aborted by the site: %s", failure)

    async def handle_response(self, response):
        request = response.request
        url = _safe_url(response)
        method = getattr(request, "method", "?")
        try:
            status = response.status
        except Exception:
            status = "?"
        try:
            content_type = network.normalized_content_type(response)
        except Exception:
            content_type = ""
        try:
            post_fields = network.safe_post_fields(request)
        except Exception:
            post_fields = []
        try:
            request_values = network.parse_post_fields(request)
        except Exception:
            request_values = {}
        folded = {str(k).casefold(): v for k, v in request_values.items()}
        filename_hint = folded.get("filename") or folded.get("file")

        view_flow = network.is_view_flow(request, url)
        if view_flow:
            self._open_view_window(f"{method} {network.redact_url(url)}")
        in_window = self._in_view_window()

        should_read = (
            in_window
            or view_flow
            or network.is_document_content_type(content_type)
            or "json" in content_type
        ) and not network.is_static_asset(url)

        body = None
        size = None
        note = ""
        if should_read:
            try:
                body = await response.body()
                size = len(body)
            except Exception as exc:
                note = f"body-unavailable({type(exc).__name__})"
                content_length = response.headers.get("content-length", "")
                if content_length.isdigit():
                    size = int(content_length)
        else:
            content_length = response.headers.get("content-length", "")
            if content_length.isdigit():
                size = int(content_length)

        line = diagnostics.exchange(
            method, url, status, content_type, size, post_fields, note
        )
        if in_window or view_flow:
            self.view_window_events.append(line)

        if body is None or not body:
            if note:
                logger.debug("Could not read response body for %s: %s", url, note)
            return

        if len(body) > config.MAX_BODY_READ:
            diagnostics.note(
                f"body too large to classify ({len(body)} bytes > "
                f"{config.MAX_BODY_READ}): {network.redact_url(url)}"
            )
            return

        if network.is_static_asset(url):
            diagnostics.note(f"static asset, not a document: {network.redact_url(url)}")
            return

        full_body = self._assemble_range(response, url, content_type, body, line)
        if full_body is None:
            return
        body = full_body

        await self._process_body(
            response, url, content_type, body, view_flow, in_window, filename_hint
        )

        # Fires independently of the document sniffing above: a JSON-only
        # record viewer produces no document bytes at all.
        self._maybe_schedule_render_fallback(
            url, status, content_type, body, in_window, view_flow
        )

    async def handle_download(self, download):
        url = _safe_url(download)
        self._open_view_window(f"browser download from {network.redact_url(url)}")
        diagnostics.note(f"browser download started: {network.redact_url(url)}")
        try:
            suggested = download.suggested_filename or ""
        except Exception:
            suggested = ""
        try:
            path = await download.path()
            body = Path(path).read_bytes()
        except Exception as exc:
            diagnostics.note(
                f"download could not be read ({type(exc).__name__}): "
                f"{network.redact_url(url)}"
            )
            return
        line = diagnostics.exchange(
            "DOWNLOAD",
            url,
            "",
            "",
            len(body),
            [],
            f"suggested-filename={suggested}",
        )
        self.view_window_events.append(line)
        extension = network.sniff_extension(body)
        if extension is None:
            diagnostics.note(
                f"downloaded file is not a recognised document "
                f"(first bytes {body[:16]!r})"
            )
            return
        await self._save_document(
            body,
            url,
            _EXTENSION_CONTENT_TYPES.get(extension, "application/octet-stream"),
            extension,
            filename_hint=suggested,
        )

    def _assemble_range(self, response, url, content_type, body, log_line):
        try:
            status = response.status
        except Exception:
            status = "?"
        content_range = response.headers.get("content-range", "")
        if status == 200 or not content_range:
            self.range_buffers.pop(url, None)
            return body

        parsed = network.parse_content_range(content_range)
        if parsed is None:
            diagnostics.note(f"unparseable Content-Range: {content_range!r}")
            return None
        start, end, total = parsed
        buffer_ = self.range_buffers.setdefault(url, {"total": total, "chunks": {}})
        if total is not None:
            buffer_["total"] = total
        buffer_["chunks"][start] = body
        total = buffer_["total"]

        position = 0
        pieces = []
        for chunk_start in sorted(buffer_["chunks"]):
            if chunk_start > position:
                break
            chunk = buffer_["chunks"][chunk_start]
            pieces.append(chunk)
            position = chunk_start + len(chunk)

        if total is None:
            diagnostics.note(
                f"range chunk {start}-{end} of unknown total stored "
                f"({position} bytes so far)"
            )
            return None

        if position >= total:
            assembled = b"".join(pieces)
            del self.range_buffers[url]
            diagnostics.note(
                f"assembled {len(assembled)} bytes from range requests for "
                f"{network.redact_url(url)}"
            )
            return assembled

        diagnostics.note(
            f"range chunk {start}-{end}/{total} stored "
            f"({position}/{total} bytes complete)"
        )
        return None

    async def _process_body(
        self, response, url, content_type, body, view_flow, in_window, filename_hint
    ):
        # A response declared as JSON is always handled as JSON first: its
        # payload may legitimately contain the text "%PDF-" and must not be
        # mistaken for a document.
        if "json" in content_type:
            await self._handle_json_body(
                body, response, url, in_window, filename_hint
            )
            return

        # Reject HTML/error pages before any magic-byte matching, so a page
        # that merely quotes "%PDF-" can never be saved as a .pdf file.
        head = body.lstrip()[:64].lower()
        if head.startswith((b"<!doctype", b"<html", b"<head", b"<body", b"<!--")):
            diagnostics.note(
                f"HTML/error response, not a document "
                f"(content-type={content_type or '-'}, size={len(body)}): "
                f"{network.redact_url(url)}"
            )
            return

        extension = network.confirm_extension(content_type, body)

        if extension is not None:
            if extension == "pdf" and not _is_valid_pdf(body):
                diagnostics.note(
                    f"rejected: body declared/ sniffed as PDF but has no %PDF- "
                    f"signature (first bytes {body[:16]!r})"
                )
                return
            if (
                extension in _IMAGE_EXTENSIONS
                and not in_window
                and not view_flow
            ):
                diagnostics.note(
                    f"image outside a view window, not saved: "
                    f"{network.redact_url(url)}"
                )
                return
            status = _response_status(response)
            logger.info(
                "Document bytes detected (%s, %d bytes, status=%s) from %s",
                extension,
                len(body),
                status,
                network.redact_url(url),
            )
            await self._save_document(
                body,
                url,
                content_type or _EXTENSION_CONTENT_TYPES.get(extension, ""),
                extension,
                filename_hint=filename_hint,
                status=status,
            )
            return

        if network.looks_like_json("", body):
            await self._handle_json_body(
                body, response, url, in_window, filename_hint
            )
            return

        diagnostics.note(
            f"unrecognised body, not saved (content-type={content_type or '-'} "
            f"first bytes {body[:16]!r})"
        )

    async def _handle_json_body(self, body, response, url, in_window, filename_hint):
        payload = network.parse_json_body(body)
        if payload is None:
            diagnostics.note("JSON body could not be parsed")
            return
        _note_json_error(payload, url)
        criteria = _extract_criteria(payload)
        if criteria:
            self.pending_criteria.update(criteria)
            diagnostics.note(f"record criteria captured: {criteria}")
        if in_window and isinstance(payload, dict):
            keys = sorted(str(k) for k in payload.keys())
            diagnostics.note(f"JSON top-level keys: {keys}")
            if await self._handle_encrypted_envelope(
                payload, url, filename_hint, status=_response_status(response)
            ):
                return
        await self._handle_json_payload(payload, response, url, in_window, filename_hint)

    async def _handle_encrypted_envelope(
        self, payload, source_url, filename_hint, status=None
    ):
        """Handle the site's encrypted-document exchange.

        The site returns the document as an AES payload: one response carries
        {data, success, token} and a follow-up carries {iv, key, success}.
        Those must not be treated as generic document references (the base64
        key in particular looks like a relative URL).
        Returns True when the payload was consumed by this flow.
        """
        handled = False

        key_val = payload.get("key")
        if isinstance(key_val, str) and key_val:
            key_bytes = _largest_decode(key_val)
            if key_bytes is not None and len(key_bytes) in (16, 24, 32):
                self.pending_key = key_val
                self.pending_key_url = source_url
                diagnostics.note(
                    f"session key material received ({len(key_bytes)} bytes)"
                )
                handled = True

        iv_val = payload.get("iv")
        if isinstance(iv_val, str) and iv_val:
            iv_bytes = _largest_decode(iv_val)
            if iv_bytes is not None and 1 <= len(iv_bytes) <= 16:
                self.pending_iv = iv_val
                diagnostics.note(f"IV received ({len(iv_bytes)} bytes)")
                handled = True

        data_val = payload.get("data")
        if isinstance(data_val, str) and data_val:
            kind = network.reference_kind(data_val)
            if kind in ("base64", "base64url", "hex"):
                decoded = _largest_decode(data_val)
                if (
                    decoded is not None
                    and len(decoded) >= 1024
                    and network.sniff_extension(decoded) is None
                ):
                    # A new ciphertext invalidates any key from a previous record
                    self.pending_cipher_b64 = data_val
                    self.pending_cipher_url = source_url
                    self.pending_cipher_hint = filename_hint
                    self.pending_cipher_status = status
                    self.pending_key = None
                    self.pending_iv = None
                    diagnostics.note(
                        f"encrypted document payload captured "
                        f"({len(decoded)} bytes) - awaiting key material"
                    )
                    handled = True

        if handled and self.pending_cipher_b64 and self.pending_key and self.pending_iv:
            return await self._decrypt_pending()
        return handled

    async def _decrypt_pending(self) -> bool:
        page = self._open_page()
        if page is None:
            diagnostics.note("no open page available for decryption")
            return False
        diagnostics.note("decrypting captured payload via in-page WebCrypto")
        try:
            result = await page.evaluate(
                _DECRYPT_JS,
                {
                    "keyB64": self.pending_key,
                    "ivB64": self.pending_iv,
                    "dataB64": self.pending_cipher_b64,
                },
            )
        except Exception as exc:
            diagnostics.note(
                f"decryption raised in page: {type(exc).__name__}: {exc}"
            )
            return False

        for attempt in (result or {}).get("attempts", [])[:16]:
            diagnostics.note(f"  attempt: {attempt}")

        if not result or result.get("error"):
            diagnostics.note(
                f"decryption failed: {(result or {}).get('error', 'no result')}"
            )
            for name, size in (result or {}).get("successAlgs", []):
                diagnostics.note(f"  decrypted but not a document: {name} ({size})")
            if (result or {}).get("preview"):
                diagnostics.note(
                    f"  plaintext preview: {result['preview']}"
                )
            return False

        try:
            body = base64.b64decode(result["b64"])
        except Exception as exc:
            diagnostics.note(f"decrypted payload not valid base64: {exc}")
            return False

        extension = result.get("ext") or network.sniff_extension(body)
        if extension is None:
            diagnostics.note("decrypted payload is not a recognised document")
            return False
        if extension == "pdf" and not _is_valid_pdf(body):
            diagnostics.note("decrypted payload has no %PDF- signature")
            return False

        diagnostics.note(
            f"decrypted via {result.get('alg')} -> {len(body)} bytes, "
            f"{result.get('mime')}, first32={network.hex_preview(body)}"
        )
        saved = await self._save_document(
            body,
            self.pending_cipher_url or result.get("alg") or "decrypt",
            result.get("mime")
            or _EXTENSION_CONTENT_TYPES.get(extension, "application/octet-stream"),
            extension,
            filename_hint=self.pending_cipher_hint,
            status=self.pending_cipher_status,
        )
        if saved:
            self.pending_cipher_b64 = None
            self.pending_cipher_url = None
            self.pending_cipher_hint = None
            self.pending_cipher_status = None
            self.pending_key = None
            self.pending_iv = None
        return bool(saved)

    # ------------------------------------------------------------------
    # render fallback: JSON-only records (no document bytes on the wire)
    # ------------------------------------------------------------------
    def _render_trigger_matches(self, url) -> bool:
        if not config.RENDER_FALLBACK_ENABLED:
            return False
        low = (url or "").casefold()
        return any(
            str(fragment).casefold() in low
            for fragment in config.RENDER_FALLBACK_URL_FRAGMENTS
        )

    @staticmethod
    def _looks_like_document_envelope(body: bytes) -> bool:
        """True for payloads this session already knows how to turn into a
        document (the encrypted e-Records exchange), which must not also be
        rendered as a screenshot."""
        try:
            payload = network.parse_json_body(body)
        except Exception:
            return False
        if not isinstance(payload, dict):
            return False
        keys = {str(k).casefold() for k in payload}
        return ("data" in keys and "token" in keys) or ("key" in keys and "iv" in keys)

    def _hint_render_fragment(self, url):
        if url in self.render_hint_urls:
            return
        self.render_hint_urls.add(url)
        diagnostics.note(
            f"JSON response in a view window did not match "
            f"RENDER_FALLBACK_URL_FRAGMENTS: {network.redact_url(url)} - if this "
            f"is the record call, add a distinctive fragment of its path to "
            f"RENDER_FALLBACK_URL_FRAGMENTS in scraper/config.py"
        )

    def _maybe_schedule_render_fallback(
        self, url, status, content_type, body, in_window, view_flow
    ):
        if not config.RENDER_FALLBACK_ENABLED or not body:
            return
        is_json = "json" in (content_type or "") or network.looks_like_json("", body)
        if not is_json:
            return
        if network.is_static_asset(url):
            return
        size = len(body)
        if (
            size < config.RENDER_FALLBACK_MIN_JSON_BYTES
            or size > config.RENDER_FALLBACK_MAX_JSON_BYTES
        ):
            return
        if not self._render_trigger_matches(url):
            if in_window or view_flow:
                self._hint_render_fragment(url)
            return
        if self._looks_like_document_envelope(body):
            diagnostics.note(
                "render fallback not needed: JSON payload is a document envelope "
                f"(handled by network capture): {network.redact_url(url)}"
            )
            return

        digest = network.sha256_hex(
            (url or "").encode("utf-8", "replace") + b"\n" + bytes(body)
        )
        if digest in self.render_fallback_seen:
            return
        self.render_fallback_seen.add(digest)

        diagnostics.note(
            f"render fallback trigger matched: {network.redact_url(url)} "
            f"(status={status}, json={size} bytes)"
        )
        self._open_view_window(f"render fallback for {network.redact_url(url)}")
        if self.view_window_saved:
            diagnostics.note(
                "render fallback skipped: a document was already captured in "
                "this view window"
            )
            return
        task = asyncio.ensure_future(
            self._render_fallback(url, status, body, digest)
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _render_fallback(self, source_url, status, trigger_body, digest):
        """Render what the browser drew and save it through the normal
        dedup/metadata/hash pipeline (`_save_document`)."""
        delay = max(0.0, float(config.RENDER_FALLBACK_DELAY_SECONDS))
        diagnostics.note(
            f"render fallback: letting the page settle for {delay}s before "
            f"capturing {network.redact_url(source_url)}"
        )
        if config.RENDER_FALLBACK_WAIT_NETWORK_IDLE:
            page = self._open_page()
            if page is not None:
                try:
                    await page.wait_for_load_state("networkidle", timeout=5000)
                except Exception as exc:
                    diagnostics.note(
                        f"render fallback: network idle not reached "
                        f"({type(exc).__name__})"
                    )
        await asyncio.sleep(delay)

        if self.view_window_saved:
            diagnostics.note(
                "render fallback skipped: a document was captured while waiting"
            )
            return None

        page = self._open_page()
        if page is None or page.is_closed():
            diagnostics.note("render fallback: no open page to render")
            return None

        fmt = str(config.RENDER_FALLBACK_FORMAT or "png").casefold().lstrip(".")
        extension = "pdf" if fmt == "pdf" else "png"
        rendered = None
        if extension == "pdf":
            try:
                rendered = await page.pdf(
                    format="A4",
                    print_background=True,
                    margin={
                        "top": "10mm",
                        "bottom": "10mm",
                        "left": "10mm",
                        "right": "10mm",
                    },
                )
            except Exception as exc:
                diagnostics.note(
                    f"render fallback: page.pdf() unavailable "
                    f"({type(exc).__name__}: {exc}); using a screenshot instead"
                )
                extension = "png"
        if rendered is None:
            try:
                rendered = await page.screenshot(
                    type="png", full_page=bool(config.RENDER_FALLBACK_FULL_PAGE)
                )
            except Exception as exc:
                diagnostics.note(
                    f"render fallback: screenshot failed "
                    f"({type(exc).__name__}: {exc})"
                )
                return None
        if not rendered:
            diagnostics.note("render fallback: renderer produced no bytes")
            return None

        try:
            page_url = page.url or ""
        except Exception:
            page_url = ""
        out_ct = "application/pdf" if extension == "pdf" else "image/png"
        diagnostics.exchange(
            "RENDER",
            page_url or source_url,
            status,
            out_ct,
            len(rendered),
            [],
            f"trigger={network.redact_url(source_url)} json_bytes={len(trigger_body)}",
        )
        saved = await self._save_document(
            rendered,
            source_url,
            out_ct,
            extension,
            filename_hint=f"render-{digest[:8]}",
            status=status,
        )
        if saved:
            diagnostics.note(
                f"render fallback saved the rendered record -> {saved} "
                f"(page={network.redact_url(page_url)})"
            )
        return saved

    def _open_page(self):
        for page in list(self.context.pages):
            if not page.is_closed():
                return page
        return None

    async def _handle_json_payload(
        self, payload, response, source_url, in_window, filename_hint=None
    ):
        refs = network.extract_document_references(payload)
        if not refs:
            diagnostics.note("JSON payload contains no document reference")
            return
        for key, value in refs:
            diagnostics.note(
                f"JSON document reference [{key}] {network.describe_reference(value)}"
            )
            if network.is_data_url(value):
                decoded = network.decode_data_url(value)
                if decoded:
                    await self._save_decoded(
                        decoded,
                        source_url,
                        f"data-url:{key}",
                        filename_hint,
                        status=_response_status(response),
                    )
                    continue
            saved = await self._try_decode_candidates(
                value, source_url, key, filename_hint,
                status=_response_status(response),
            )
            if saved:
                continue
            if value.startswith("blob:"):
                diagnostics.note(
                    "blob reference found - relying on the underlying network "
                    "response that produced it (already watched)"
                )
                continue
            if self._is_fetchable_reference(value) and in_window:
                await self._follow_reference(value, response, source_url, filename_hint)

    async def _try_decode_candidates(
        self, value, source_url, key, filename_hint=None, status=None
    ) -> bool:
        """Try every plausible encoding of an opaque reference and save it
        when the decoded bytes are a recognised document."""
        candidates = network.decode_candidates(value)
        if not candidates:
            diagnostics.note(
                f"[{key}] no recognised encoding (len={len(value)}, "
                f"preview={value[:24]!r})"
            )
            return False
        seen = set()
        for strategy, data in candidates:
            digest = network.sha256_hex(data)
            if digest in seen:
                continue
            seen.add(digest)
            extension = network.sniff_extension(data)
            diagnostics.note(
                f"[{key}] {strategy} -> {len(data)} bytes, "
                f"sniff={extension or 'none'}, first32={network.hex_preview(data)}"
            )
            if extension is None:
                continue
            if extension == "pdf" and not _is_valid_pdf(data):
                diagnostics.note(f"[{key}] {strategy}: no %PDF- signature")
                continue
            await self._save_document(
                data,
                source_url,
                _EXTENSION_CONTENT_TYPES.get(extension, "application/octet-stream"),
                extension,
                filename_hint=filename_hint or f"{strategy}:{key}",
                status=status,
            )
            return True
        diagnostics.note(f"[{key}] no candidate decoded to a document")
        return False

    def _is_fetchable_reference(self, value: str) -> bool:
        if value.startswith(("http://", "https://")):
            return True
        if value.startswith("//"):
            return False
        if value.startswith("/"):
            return not _looks_like_encoded_blob(value)
        if value.startswith("./") or value.startswith("../"):
            return True
        return False

    async def _save_decoded(
        self, body, source_url, origin, filename_hint=None, status=None
    ):
        extension = network.sniff_extension(body)
        if extension is None:
            diagnostics.note(f"{origin}: decoded payload is not a document")
            return
        if extension == "pdf" and not _is_valid_pdf(body):
            diagnostics.note(f"{origin}: decoded payload has no %PDF- signature")
            return
        await self._save_document(
            body,
            source_url,
            _EXTENSION_CONTENT_TYPES.get(extension, "application/octet-stream"),
            extension,
            filename_hint=filename_hint or origin,
            status=status,
        )

    async def _follow_reference(self, value, response, source_url, filename_hint=None):
        if value in self.followed_urls:
            return
        if self.followup_budget <= 0:
            diagnostics.note("follow-up budget exhausted, reference not fetched")
            return
        page = None
        try:
            page = response.frame.page
        except Exception:
            page = None
        if page is None or page.is_closed():
            for candidate in list(self.context.pages):
                if not candidate.is_closed():
                    page = candidate
                    break
        if page is None:
            diagnostics.note("no open page available for follow-up fetch")
            return

        resolved = urllib.parse.urljoin(page.url or source_url, value)
        if not resolved.startswith(("http://", "https://")):
            diagnostics.note(f"reference not fetchable: {value[:200]}")
            return

        self.followed_urls.add(resolved)
        self.followup_budget -= 1
        diagnostics.note(
            f"following document reference via authenticated page fetch: "
            f"{network.redact_url(resolved)}"
        )
        logger.info("Following document reference: %s", network.redact_url(resolved))
        try:
            result = await page.evaluate(_FOLLOW_FETCH_JS, resolved)
        except Exception as exc:
            diagnostics.note(f"follow-up fetch failed ({type(exc).__name__})")
            return
        if not isinstance(result, dict):
            diagnostics.note("follow-up fetch returned no data")
            return
        if result.get("error"):
            diagnostics.note(f"follow-up fetch error: {result['error']}")
            return
        diagnostics.exchange(
            "FETCH",
            resolved,
            result.get("status", "?"),
            result.get("contentType", ""),
            None,
            [],
            "follow-up of JSON document reference",
        )
        if not result.get("ok"):
            diagnostics.note(f"follow-up fetch HTTP {result.get('status')}")
            return

        try:
            body = base64.b64decode(result.get("b64", ""), validate=False)
        except Exception:
            diagnostics.note("follow-up fetch payload was not valid base64")
            return
        extension = network.sniff_extension(body)
        if extension is None:
            diagnostics.note(
                f"follow-up payload is not a document "
                f"(first bytes {body[:16]!r})"
            )
            return
        if extension == "pdf" and not _is_valid_pdf(body):
            diagnostics.note("follow-up payload has no %PDF- signature")
            return
        await self._save_document(
            body,
            resolved,
            result.get("contentType")
            or _EXTENSION_CONTENT_TYPES.get(extension, ""),
            extension,
            filename_hint=filename_hint,
            status=result.get("status"),
        )

    async def _save_document(
        self, body, url, content_type, extension, filename_hint=None, status=None
    ):
        digest = network.sha256_hex(body)
        if storage.is_duplicate(digest, self.known_hashes):
            logger.warning(
                "Duplicate document skipped (already downloaded): %s (sha256 %s...)",
                network.redact_url(url),
                digest[:12],
            )
            diagnostics.note(
                f"duplicate skipped (sha256 {digest[:12]}...): "
                f"{network.redact_url(url)}"
            )
            self.view_window_saved = True
            return None

        if self.delay_seconds > 0:
            await asyncio.sleep(self.delay_seconds)

        criteria = await self.read_search_criteria()
        merged = SearchCriteria(
            survey_no=self.pending_criteria.get("survey_no") or criteria.survey_no,
            hissa_no=self.pending_criteria.get("hissa_no") or criteria.hissa_no,
            old_survey_no=self.pending_criteria.get("old_survey_no")
            or criteria.old_survey_no,
            gat_no=self.pending_criteria.get("gat_no") or criteria.gat_no,
            from_year=self.pending_criteria.get("from_year") or criteria.from_year,
            to_year=self.pending_criteria.get("to_year") or criteria.to_year,
        )

        record_id = self.next_id
        self.next_id += 1

        safe_stem = _sanitize_stem(_criteria_stem(merged))
        if not safe_stem and filename_hint:
            safe_stem = _sanitize_stem(filename_hint)
        saved_name = _build_saved_name(record_id, safe_stem, extension)

        if not isinstance(body, (bytes, bytearray)):
            raise TypeError(
                f"refusing to save non-binary document body "
                f"({type(body).__name__}) from {network.redact_url(url)}"
            )

        target = storage.save_document(body, saved_name)
        verified_ok, verified_detail = storage.verify_saved_file(target)
        storage.append_hash(digest, self.known_hashes)
        storage.append_metadata_row(
            DocumentRecord(
                id=record_id,
                criteria=merged,
                source_url=network.redact_url(url),
                saved_filename=saved_name,
                content_type=content_type,
                downloaded_at=dt.datetime.now(dt.timezone.utc).isoformat(
                    timespec="seconds"
                ),
            )
        )
        self.pending_criteria = {}
        self.view_window_saved = True
        diagnostics.note(
            f"SAVED document #{record_id} -> {saved_name} | "
            f"url={network.redact_url(url)} | status={status or '?'} | "
            f"content-type={content_type} | size={len(body)} | "
            f"sha256={digest[:12]}... | verify={'OK' if verified_ok else 'FAILED'} "
            f"({verified_detail})"
        )
        logger.info(
            "Saved document #%d -> %s | url=%s | status=%s | content-type=%s | "
            "%d bytes | sha256=%s... | %s",
            record_id,
            target,
            network.redact_url(url),
            status or "?",
            content_type,
            len(body),
            digest[:12],
            verified_detail,
        )
        return saved_name

    async def read_search_criteria(self):
        last_fields = None
        for page in list(self.context.pages):
            if page.is_closed():
                continue
            try:
                snapshot = await page.evaluate(_FORM_SNAPSHOT_JS)
            except Exception:
                continue
            if not isinstance(snapshot, list) or not snapshot:
                continue
            found = _criteria_from_snapshot(snapshot)
            if found:
                diagnostics.note(f"search form criteria: {found}")
                return SearchCriteria(
                    survey_no=found.get("survey_no", ""),
                    hissa_no=found.get("hissa_no", ""),
                    old_survey_no=found.get("old_survey_no", ""),
                    gat_no=found.get("gat_no", ""),
                    from_year=found.get("from_year", ""),
                    to_year=found.get("to_year", ""),
                )
            last_fields = [
                f"{it.get('id') or it.get('name') or it.get('ph') or it.get('tag')}"
                f"={it.get('val', '')[:40]}"
                for it in snapshot
                if isinstance(it, dict) and str(it.get("val", "")).strip()
            ]
        if last_fields is None:
            diagnostics.note("no open page available to read the search form")
        else:
            diagnostics.note(
                "search form has no recognised criteria fields; "
                f"non-empty inputs: {last_fields[:20]}"
            )
        return SearchCriteria()


# Ordered: more specific patterns must come first.
_CRITERIA_PATTERNS = (
    ("old_survey_no", re.compile(r"old.{0,6}survey|survey.{0,6}old|oldsurvey", re.I), None),
    ("survey_no", re.compile(r"survey", re.I), re.compile(r"\bold\b", re.I)),
    ("hissa_no", re.compile(r"hissa", re.I), None),
    ("gat_no", re.compile(r"\bgat\b|gatno|gat_no|gatno", re.I), None),
    (
        "from_year",
        re.compile(r"from.{0,6}year|frm.{0,6}year|fromyear|year.{0,6}from", re.I),
        None,
    ),
    (
        "to_year",
        re.compile(r"\bto\b.{0,6}year|to.{0,6}year|toyear|year.{0,6}\bto\b", re.I),
        re.compile(r"from", re.I),
    ),
)


def _criteria_from_snapshot(items) -> dict:
    found = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        value = str(item.get("val") or "").strip()
        if not value:
            continue
        haystack = " ".join(
            str(item.get(k) or "") for k in ("id", "name", "ph", "holder", "tag")
        )
        for field, pattern, exclude in _CRITERIA_PATTERNS:
            if field in found:
                continue
            if exclude and exclude.search(haystack):
                continue
            if pattern.search(haystack):
                found[field] = value
                break
    return found


def _extract_criteria(payload) -> dict:
    found = {}

    def walk(node, depth=0):
        if depth > 8:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                mapped = _CRITERIA_KEY_MAP.get(str(key).lower())
                if mapped and isinstance(value, (str, int, float)):
                    text = str(value).strip()
                    if text:
                        found.setdefault(mapped, text)
                else:
                    if isinstance(value, str):
                        nested = _maybe_json(value)
                        walk(nested if nested is not None else value, depth + 1)
                    else:
                        walk(value, depth + 1)
        elif isinstance(node, list):
            for item in node:
                walk(item, depth + 1)

    walk(payload)
    return found


def _maybe_json(value: str):
    """Return the parsed object when a string carries double-encoded JSON."""
    stripped = value.strip()
    if len(stripped) < 2 or stripped[0] not in "{[":
        return None
    try:
        return json.loads(stripped)
    except Exception:
        return None