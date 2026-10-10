import csv
import uuid

from . import config
from .logger import get_logger

logger = get_logger()


def ensure_dirs():
    for directory in (config.DATA_DIR, config.DOCUMENTS_DIR, config.LOGS_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def init_metadata_csv():
    ensure_dirs()
    if not config.METADATA_CSV.exists():
        with config.METADATA_CSV.open("w", newline="", encoding="utf-8") as fh:
            csv.DictWriter(fh, fieldnames=config.METADATA_FIELDS).writeheader()
        logger.info("Created metadata.csv with header.")


def load_hashes():
    ensure_dirs()
    hashes = set()
    if config.HASHES_FILE.exists():
        with config.HASHES_FILE.open("r", encoding="utf-8") as fh:
            for line in fh:
                digest = line.strip()
                if digest:
                    hashes.add(digest)
    return hashes


def next_id():
    init_metadata_csv()
    count = 0
    with config.METADATA_CSV.open("r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh, fieldnames=config.METADATA_FIELDS)
        next(reader, None)
        count = sum(1 for _ in reader)
    return count + 1


def is_duplicate(digest, known_hashes):
    return digest in known_hashes


def verify_saved_file(path):
    """Post-write check: the file exists, is non-empty, and PDFs start with %PDF-."""
    if not path.exists():
        return False, "file missing after write"
    size = path.stat().st_size
    if size <= 0:
        return False, "file is empty"
    with path.open("rb") as fh:
        head = fh.read(1024)
    if path.suffix.lower() == ".pdf":
        stripped = head.lstrip()[:64].lower()
        if stripped.startswith((b"<!doctype", b"<html", b"<head", b"<body", b"<!--")):
            return False, f"HTML/error page, not a PDF (first bytes {head[:16]!r})"
        if b"%PDF-" not in head:
            return False, f"not a PDF (first bytes {head[:16]!r})"
        return True, f"verified PDF, {size} bytes, header={head[:8]!r}"
    return True, f"verified {size} bytes, magic={head[:8]!r}"


def save_document(body, filename):
    """Write raw bytes to disk in binary mode, then verify the result.

    `body` must be bytes; it is written with open(..., "wb") so the PDF/image
    is stored byte-for-byte and never passes through a text codec.
    """
    if not isinstance(body, (bytes, bytearray)):
        raise TypeError(f"save_document expects bytes, got {type(body).__name__}")
    ensure_dirs()
    target = config.DOCUMENTS_DIR / filename
    if target.exists():
        target = target.with_name(f"{target.stem}-{uuid.uuid4().hex[:8]}{target.suffix}")
    with target.open("wb") as fh:
        fh.write(bytes(body))
    ok, detail = verify_saved_file(target)
    if not ok:
        target.unlink(missing_ok=True)
        raise ValueError(f"post-save validation failed for {filename}: {detail}")
    logger.info(
        "Saved file %s -> %s (%d bytes)", target.name, target, target.stat().st_size
    )
    logger.info("Verified %s: %s", target.name, detail)
    return target


def append_hash(digest, known_hashes):
    ensure_dirs()
    with config.HASHES_FILE.open("a", encoding="utf-8") as fh:
        fh.write(digest + "\n")
    known_hashes.add(digest)


def append_metadata_row(record):
    init_metadata_csv()
    row = {
        "id": record.id,
        "survey_no": record.criteria.survey_no,
        "hissa_no": record.criteria.hissa_no,
        "old_survey_no": record.criteria.old_survey_no,
        "gat_no": record.criteria.gat_no,
        "from_year": record.criteria.from_year,
        "to_year": record.criteria.to_year,
        "source_url": record.source_url,
        "saved_filename": record.saved_filename,
        "content_type": record.content_type,
        "downloaded_at": record.downloaded_at,
    }
    with config.METADATA_CSV.open("a", newline="", encoding="utf-8") as fh:
        csv.DictWriter(fh, fieldnames=config.METADATA_FIELDS).writerow(row)
    logger.info("Appended metadata row for document #%s to metadata.csv", record.id)