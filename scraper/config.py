from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"
DOCUMENTS_DIR = DATA_DIR / "documents"
LOGS_DIR = BASE_DIR / "logs"
PROFILE_DIR = BASE_DIR / ".playwright-profile"
SELENIUM_PROFILE_DIR = BASE_DIR / ".selenium-profile"
SELENIUM_DOWNLOAD_DIR = DATA_DIR / "downloads"
SELENIUM_HEADLESS = False
SELENIUM_PAGE_LOAD_TIMEOUT = 60
SELENIUM_SCRIPT_TIMEOUT = 90

METADATA_CSV = DATA_DIR / "metadata.csv"
HASHES_FILE = DATA_DIR / "downloaded_hashes.txt"

DEBUG_NET_FILE = LOGS_DIR / "document_network_debug.txt"

TARGET_URL = "https://aapleabhilekh.mahabhumi.gov.in/erecords/"

DOCUMENT_CONTENT_TYPES = {
    "application/pdf": "pdf",
    "application/x-pdf": "pdf",
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/tiff": "tif",
    "image/gif": "gif",
    "image/bmp": "bmp",
    "application/octet-stream": None,
}

DOCUMENT_CT_HINTS = ("pdf", "octet-stream", "download", "binary")

VIEW_FLOW_URL_FRAGMENTS = (
    "getdoc",
    "viewdoc",
    "viewfile",
    "getfile",
    "filepreview",
    "showdocument",
    "downloadfile",
)

VIEW_FLOW_POST_FIELDS = ("distcode", "repository", "filename")

# --- render fallback -------------------------------------------------------
# Some viewers never send a document at all: the "View" click returns pure
# JSON and JavaScript draws the record table in the browser.  There is no
# PDF/image in the traffic to sniff, so when a response matching one of these
# fragments arrives, the page itself is rendered (screenshot, or page.pdf()
# when headless) and saved through the normal pipeline.
#
# Every portal names this endpoint differently.  Open
# logs/document_network_debug.txt after clicking "View", find the call that
# returns the record JSON, and add a distinctive fragment of its URL here.
RENDER_FALLBACK_URL_FRAGMENTS = (
    "getrecord",
    "viewrecord",
    "recordview",
    "getrecorddetail",
    "fetchrecord",
    "retrieverecord",
    "getextract",
    "getsatbara",
    "satbara",
    "get712",
    "recorddata",
    "getdetails",
)

RENDER_FALLBACK_ENABLED = True
RENDER_FALLBACK_FORMAT = "png"  # "png" (any mode) or "pdf" (headless only)
RENDER_FALLBACK_DELAY_SECONDS = 2.5  # time to let the page draw the record
RENDER_FALLBACK_WAIT_NETWORK_IDLE = True
RENDER_FALLBACK_FULL_PAGE = True
RENDER_FALLBACK_MIN_JSON_BYTES = 200  # ignore tiny ack/lookup responses
RENDER_FALLBACK_MAX_JSON_BYTES = 2 * 1024 * 1024
# When a view window closes with no document (the record is rendered by
# JavaScript instead of being downloaded), save the rendered page anyway so
# the record exists in the dataset in "downloaded" form.
RENDER_ON_EMPTY_VIEW_WINDOW = True

STATIC_ASSET_FRAGMENTS = (
    ".js",
    ".css",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    "captcha",
    "logo",
    "favicon",
    "spinner",
    "loader",
    "banner",
    "sprite",
)

REQUEST_DELAY_SECONDS = 1.0

VIEW_WINDOW_SECONDS = 20.0
FOLLOWUP_DELAY_SECONDS = 2.0
MAX_BODY_READ = 64 * 1024 * 1024

METADATA_FIELDS = [
    "id",
    "survey_no",
    "hissa_no",
    "old_survey_no",
    "gat_no",
    "from_year",
    "to_year",
    "source_url",
    "saved_filename",
    "content_type",
    "downloaded_at",
]