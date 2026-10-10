import datetime as dt
import threading

from . import config, network
from .logger import get_logger

logger = get_logger()
_lock = threading.Lock()


def _write(text):
    config.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    with _lock:
        with config.DEBUG_NET_FILE.open("a", encoding="utf-8") as fh:
            fh.write(text + "\n")


def header(title):
    stamp = dt.datetime.now().isoformat(timespec="seconds")
    _write("")
    _write("=" * 100)
    _write(f"{title} | {stamp}")
    _write("=" * 100)


def exchange(method, url, status, content_type, size, post_fields=(), note=""):
    size_text = "?" if size is None else str(size)
    fields = ", ".join(post_fields) if post_fields else "-"
    if len(fields) > 400:
        fields = fields[:400] + "...(truncated)"
    line = (
        f"{method:<8} | {network.redact_url(url)} | status={status} | "
        f"content-type={content_type or '-'} | size={size_text} | "
        f"post-fields=[{fields}]"
    )
    if note:
        line += f" | {note}"
    stamp = dt.datetime.now().strftime("%H:%M:%S")
    _write(f"{stamp} | {line}")
    logger.debug(line)
    return line


def note(text):
    stamp = dt.datetime.now().strftime("%H:%M:%S")
    _write(f"{stamp} | NOTE   | {text}")
    logger.debug("NOTE   | %s", text)


def write_block(lines):
    stamp = dt.datetime.now().isoformat(timespec="seconds")
    _write("")
    _write(f"--- {stamp} ---")
    for line in lines:
        _write(line)
    _write("")