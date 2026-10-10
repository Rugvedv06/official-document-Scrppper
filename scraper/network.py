import hashlib
import json
import re
import urllib.parse
from typing import Optional

from . import config

_MAGIC_EXTENSIONS = (
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"%PDF-", "pdf"),
    (b"\xff\xd8\xff", "jpg"),
    (b"II*\x00", "tif"),
    (b"MM\x00*", "tif"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"BM", "bmp"),
)

_SENSITIVE_FIELD_RE = re.compile(
    r"token|session|auth|password|passwd|otp|secret|cookie|bearer|"
    r"key|mobile|phone|email|userid|username|licence|license",
    re.I,
)

_CONTENT_RANGE_RE = re.compile(r"bytes\s+(\d+)-(\d+)/(\d+|\*)")

_MAX_FIELD_VALUE_LEN = 48
_MAX_POST_FIELDS = 16

_DOC_REF_KEYS = (
    "file",
    "filename",
    "filepath",
    "fileurl",
    "file_url",
    "document",
    "documenturl",
    "document_url",
    "doc",
    "docurl",
    "download",
    "downloadurl",
    "download_url",
    "path",
    "url",
    "uri",
    "href",
    "src",
    "location",
    "repository",
    "data",
    "base64",
    "content",
    "pdf",
    "filedata",
    "binary",
    "blob",
)


def normalized_content_type(response) -> str:
    raw = response.headers.get("content-type", "") or ""
    return raw.split(";")[0].strip().lower()


def redact_url(url: str) -> str:
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    if not parts.query:
        return url
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    redacted = [
        (key, "<redacted>" if _SENSITIVE_FIELD_RE.search(key) else value)
        for key, value in pairs
    ]
    query = urllib.parse.urlencode(redacted)
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, query, parts.fragment)
    )


def _truncate(value, limit=_MAX_FIELD_VALUE_LEN) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def parse_multipart_fields(data: str) -> dict:
    """Parse a multipart/form-data body without needing the content-type header.

    Needed because urllib.parse.parse_qs cannot handle multipart bodies and
    would otherwise emit the entire raw body (including the anti-forgery
    token) as if it were a single query-string key.
    """
    fields = {}
    if not data:
        return fields
    first = data.split("\n", 1)[0].strip("\r\n")
    if not first.startswith("--"):
        return fields
    for part in data.split(first):
        part = part.strip("\r\n")
        if not part or part.startswith("--"):
            continue
        name_match = re.search(
            r"Content-Disposition:.*?name=\"([^\"]+)\"", part, re.I | re.S
        )
        if not name_match:
            continue
        remainder = part[name_match.end() :]
        blank = re.search(r"\r?\n\r?\n", remainder)
        value = remainder[blank.end() :] if blank else remainder
        fields[name_match.group(1)] = value.strip("\r\n")
    return fields


def _post_items(request, data) -> list:
    """Return [(name, value)] for a request body, safely for any encoding."""
    if data.lstrip().startswith("--"):
        return list(parse_multipart_fields(data).items())
    try:
        as_json = request.post_data_json
    except Exception:
        as_json = None
    if isinstance(as_json, dict):
        items = []
        for key, value in as_json.items():
            if isinstance(value, (str, int, float)):
                items.append((str(key), str(value)))
            else:
                items.append((str(key), "<non-scalar>"))
        return items
    parsed = urllib.parse.parse_qs(data, keep_blank_values=True)
    return [(key, values[0] if values else "") for key, values in parsed.items()]


def safe_post_fields(request) -> list:
    try:
        data = request.post_data
    except Exception:
        return []
    if not data:
        return []
    try:
        items = _post_items(request, data)
    except Exception:
        # Never fall back to echoing the raw body: it may carry the token.
        return ["<unparseable-body>"]
    fields = []
    for key, value in items:
        if _SENSITIVE_FIELD_RE.search(key) or key.startswith("__"):
            fields.append(f"{key}=<redacted>")
        else:
            fields.append(f"{key}={_truncate(value)}")
        if len(fields) >= _MAX_POST_FIELDS:
            fields.append("...")
            break
    return fields


def request_post_field_names(request) -> list:
    try:
        data = request.post_data
    except Exception:
        return []
    if not data:
        return []
    try:
        return [str(name) for name, _ in _post_items(request, data)]
    except Exception:
        return []


def is_view_flow(request, url: str) -> bool:
    lowered = url.lower()
    if any(fragment in lowered for fragment in config.VIEW_FLOW_URL_FRAGMENTS):
        return True
    try:
        post_fields = {name.lower() for name in request_post_field_names(request)}
    except Exception:
        return False
    markers = {name for name in config.VIEW_FLOW_POST_FIELDS}
    return len(post_fields & markers) >= 2


def is_static_asset(url: str) -> bool:
    lowered = url.lower()
    path = urllib.parse.urlsplit(lowered).path
    return any(fragment in path for fragment in config.STATIC_ASSET_FRAGMENTS)


def is_document_content_type(content_type: str) -> bool:
    if content_type in config.DOCUMENT_CONTENT_TYPES:
        return True
    return any(hint in content_type for hint in config.DOCUMENT_CT_HINTS)


def looks_like_json(content_type: str, body: bytes) -> bool:
    if "json" in content_type:
        return True
    head = body.lstrip()[:1]
    return head in (b"{", b"[")


def sniff_extension(body: bytes) -> Optional[str]:
    if not body:
        return None
    # PDF allows junk before the header (within the first 1024 bytes).
    if b"%PDF-" in body[:1024]:
        return "pdf"
    for magic, extension in _MAGIC_EXTENSIONS:
        if magic == b"%PDF-":
            continue
        if body.startswith(magic):
            return extension
    return None


def _expected_magic(extension: str) -> Optional[bytes]:
    for magic, ext in _MAGIC_EXTENSIONS:
        if ext == extension:
            return magic
    return None


def candidate_extension(content_type: str) -> Optional[str]:
    if content_type in config.DOCUMENT_CONTENT_TYPES:
        return config.DOCUMENT_CONTENT_TYPES[content_type]
    return None


def confirm_extension(content_type: str, body: bytes) -> Optional[str]:
    extension = sniff_extension(body)
    if extension is not None:
        return extension
    declared = candidate_extension(content_type)
    if declared is None:
        return None
    expected_magic = _expected_magic(declared)
    if expected_magic and not body.startswith(expected_magic):
        return None
    return declared


def parse_content_range(value: str):
    match = _CONTENT_RANGE_RE.search(value or "")
    if not match:
        return None
    start, end = int(match.group(1)), int(match.group(2))
    total = None if match.group(3) == "*" else int(match.group(3))
    return start, end, total


def parse_json_body(body: bytes):
    try:
        return json.loads(body.decode("utf-8-sig", errors="strict"))
    except Exception:
        try:
            return json.loads(body.decode("latin-1"))
        except Exception:
            return None


def extract_document_references(payload):
    refs = []

    def walk(node, depth=0):
        if depth > 8:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, str) and value:
                    if value.lstrip()[:1] == "<":
                        continue
                    if str(key).lower() in _DOC_REF_KEYS:
                        refs.append((str(key), value))
                    elif _looks_like_doc_reference(value):
                        refs.append((str(key), value))
                else:
                    walk(value, depth + 1)
        elif isinstance(node, list):
            for item in node:
                walk(item, depth + 1)

    walk(payload)
    seen = set()
    unique = []
    for key, value in refs:
        marker = (key, value)
        if marker in seen:
            continue
        seen.add(marker)
        unique.append((key, value))
    return unique


def _looks_like_doc_reference(value: str) -> bool:
    lowered = value.lower()
    if lowered.startswith(("http://", "https://", "/", "./", "../", "blob:", "data:")):
        return True
    return any(
        lowered.endswith(ext)
        for ext in (".pdf", ".jpg", ".jpeg", ".png", ".tif", ".tiff", ".gif", ".bmp")
    )


def is_data_url(value: str) -> bool:
    return value.startswith("data:") and ";base64," in value[:64].lower()


def decode_data_url(value: str):
    header, _, encoded = value.partition(",")
    if not _:
        return None
    if "base64" not in header.lower():
        return None
    import base64

    try:
        return base64.b64decode(encoded, validate=False)
    except Exception:
        return None


def is_base64_blob(value: str) -> bool:
    if len(value) < 256:
        return False
    stripped = re.sub(r"\s+", "", value)
    if len(stripped) % 4 != 0:
        return False
    return re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", stripped) is not None


def decode_base64_blob(value: str) -> Optional[bytes]:
    import base64

    stripped = re.sub(r"\s+", "", value)
    try:
        return base64.b64decode(stripped, validate=False)
    except Exception:
        return None


def sha256_hex(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def hex_preview(body: bytes, size: int = 32) -> str:
    chunk = body[:size]
    hexs = " ".join(f"{b:02x}" for b in chunk)
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return f"{hexs} |{text}|"


def describe_reference(value: str) -> str:
    return f"len={len(value)} kind={reference_kind(value)}"


def reference_kind(value: str) -> str:
    if value.startswith("data:"):
        return "data-url"
    stripped = value.lstrip()
    if stripped[:1] == "<":
        return "markup"
    if value.startswith(("http://", "https://", "/", "./", "../", "blob:")):
        return "url"
    compact = re.sub(r"\s+", "", value)
    if not compact:
        return "empty"
    if re.fullmatch(r"[0-9a-fA-F]+", compact) and len(compact) % 2 == 0:
        # check hex first: hex is a subset of the base64 alphabet
        return "hex"
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        return "base64"
    if re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", compact):
        return "base64url"
    return "other"


def decode_candidates(value: str) -> list:
    """Return [(strategy, bytes)] for every plausible encoding of a value.

    The caller keeps the first candidate whose bytes sniff as a document, so
    an opaque string (encrypted, url-safe base64, hex, ...) is still captured
    without having to guess the site's encoding in advance.
    """
    candidates = []
    if value.startswith("data:"):
        decoded = decode_data_url(value)
        if decoded:
            candidates.append(("data-url", decoded))
        return candidates
    if value.lstrip()[:1] == "[":
        decoded = _decode_int_array(value)
        if decoded:
            candidates.append(("int-array", decoded))
    compact = re.sub(r"\s+", "", value)
    if not compact:
        return candidates
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        decoded = _b64(compact)
        if decoded:
            candidates.append(("base64", decoded))
    if re.fullmatch(r"[A-Za-z0-9_\-]+={0,2}", compact):
        alt = compact.replace("-", "+").replace("_", "/")
        alt += "=" * (-len(alt) % 4)
        decoded = _b64(alt)
        if decoded:
            candidates.append(("base64url", decoded))
    if re.fullmatch(r"[0-9a-fA-F]+", compact) and len(compact) % 2 == 0:
        try:
            candidates.append(("hex", bytes.fromhex(compact)))
        except ValueError:
            pass

    # If none of the direct encodings look like a document, the payload may be
    # nested (base64 of base64) or compressed - expand those one level.
    expanded = []
    for strategy, data in candidates:
        if sniff_extension(data) is not None:
            continue
        for sub_strategy, sub in _expand(data):
            expanded.append((f"{strategy}+{sub_strategy}", sub))
    candidates.extend(expanded)
    return candidates[:8]


def _expand(data: bytes) -> list:
    out = []
    if not data:
        return out
    try:
        text = data.decode("ascii")
    except Exception:
        text = None
    if text:
        compact = re.sub(r"\s+", "", text)
        if len(compact) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=\-_]+", compact):
            inner = _b64(compact.replace("-", "+").replace("_", "/"))
            if inner and inner != data:
                out.append(("nested-base64", inner))
    import gzip
    import zlib

    if data[:2] == b"\x1f\x8b":
        try:
            decoded = gzip.decompress(data)
            if decoded and decoded != data:
                out.append(("gzip", decoded))
        except Exception:
            pass
    if data[:1] in (b"\x78", b"\x01", b"\x5e", b"\x9c", b"\xda"):
        try:
            decoded = zlib.decompress(data)
            if decoded and decoded != data:
                out.append(("zlib", decoded))
        except Exception:
            pass
    return out


def _b64(text: str):
    import base64

    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.b64decode(padded, validate=False)
    except Exception:
        return None


def _decode_int_array(value: str):
    try:
        import json

        parsed = json.loads(value)
        if isinstance(parsed, list) and parsed and all(
            isinstance(item, int) and 0 <= item <= 255 for item in parsed
        ):
            return bytes(parsed)
    except Exception:
        return None
    return None


def parse_post_fields(request) -> dict:
    try:
        data = request.post_data
    except Exception:
        return {}
    if not data:
        return {}
    try:
        items = _post_items(request, data)
    except Exception:
        return {}
    return {
        k: v
        for k, v in items
        if not k.startswith("__") and not _SENSITIVE_FIELD_RE.search(k)
    }