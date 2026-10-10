# Maharashtra e-Records document scraper (manual mode)

A Python / Playwright tool that collects historical land-record documents from the
Maharashtra e-Records portal (<https://aapleabhilekh.mahabhumi.gov.in/erecords/>)
to build an OCR dataset.

This is a **manual-mode** scraper. It does **not** automate login, CAPTCHA, OTP,
search, or clicking "View". A real user performs those actions in the opened
Chromium browser; the scraper only watches the network traffic and saves the
legitimate documents the website produces in response to a "View" click.

## Legal / usage considerations

- Use only in accordance with the website's terms of service and applicable law.
- Only collect records you are authorized to view.
- The tool deliberately does **not** bypass CAPTCHA, OTP, login, access
  controls, or rate limits. All authentication is done manually by the user.
- No hardcoded cookies, tokens, passwords, or `__RequestVerificationToken`
  values are used, stored, written into the dataset, or logged.
- Keep downloads gentle (see `--delay`) and do not use the data for anything the
  site or the law disallows.

## Project structure

```
CAPSSS/
├── requirements.txt
├── scraper/
│   ├── __init__.py
│   ├── __main__.py      # python -m scraper entry point
│   ├── cli.py           # CLI arguments, browser launch, main loop
│   ├── config.py        # paths, URLs, content-type map, delays
│   ├── diagnostics.py   # redacted network dump -> logs/document_network_debug.txt
│   ├── logger.py        # console + file logging (logs/scraper.log)
│   ├── models.py        # SearchCriteria / DocumentRecord dataclasses
│   ├── network.py       # response sniffing, content-type checks, POST parsing
│   ├── storage.py       # documents dir, metadata.csv, hash registry
│   └── capture.py       # CaptureSession: listens for and saves documents
├── data/
│   ├── documents/       # saved PDF/JPEG/PNG documents (auto-created)
│   ├── metadata.csv     # one row per saved document (auto-created)
│   └── downloaded_hashes.txt  # SHA-256 of every saved document (auto-created)
├── logs/
│   ├── scraper.log                   # capture log (auto-created)
│   └── document_network_debug.txt    # per-exchange diagnostics (auto-created)
└── .playwright-profile/ # persistent browser session (auto-created, gitignored)
```

## Installation

Requires Python 3.9+.

```powershell
cd D:\CAPSSS
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Then install the Chromium browser Playwright needs:

```powershell
playwright install chromium
```

## How to run

```powershell
python -m scraper
```

Optional arguments:

- `--engine {playwright,selenium}` – which browser automation library drives the
  session (default `playwright`). See "Selenium engine" below.
- `--profile-dir PATH` – where the persistent browser profile lives
  (default `.playwright-profile`, or `.selenium-profile` with
  `--engine selenium`). The authenticated session is stored here and
  reused on later runs, so you usually do **not** have to log in every time.
- `--delay SECONDS` – pause before saving each document as a politeness guard
  (default `1.0`).
- `--max-seconds SECONDS` – stop automatically after a duration (default: run
  until you stop it).

Example:

```powershell
python -m scraper --profile-dir .playwright-profile --delay 1.0
python -m scraper --engine selenium
```

## Manual login process

1. The tool launches Chromium in **headed mode** and opens the e-Records home page.
2. You log in manually and complete any CAPTCHA / OTP you are presented with.
3. The session is kept in the profile directory, so subsequent runs re-open the
   same authenticated profile.
4. Press `Ctrl+C` on the console to stop; your profile and already-downloaded
   data are preserved.

## Using the scraper (manual capture loop)

1. Run `python -m scraper`.
2. After login, perform a search using the site's own forms
   (survey number, hissa, old survey, gat, years).
3. Click **View** on a result row.
4. The scraper detects the document response (by `Content-Type`: PDF, JPEG,
   PNG, TIFF, or other binary) and saves it to `data/documents/`, appends a
   metadata row, logs the event, and records its hash.
5. Repeat. Two identical re-downloads of the same file are skipped.

The search-criteria fields (survey/hissa/gat/years) are collected from two
places and merged when a document is captured: the record metadata returned by
the site (including payloads where the JSON is double-encoded as a string) and
the values still present in the search form. Any field that could not be found
stays empty in `metadata.csv`.

## How a "View" click is captured

Listeners are attached at the **browser-context** level, so responses from the
main tab, popups, and new tabs are all seen:

1. A response whose URL or POST fields match a view flow (`GetDoc/`, or a POST
   carrying `Distcode` + `Repository` + `Filename`) opens a *view window*.
2. While the window is open every exchange is logged, and its body is read.
   `206 Partial Content` byte ranges are reassembled before classification.
3. The body is classified: magic bytes first, then `Content-Type`, then JSON.
   - Document bytes -> saved.
   - JSON -> record criteria are extracted (survey/hissa/gat/years) and any
     embedded document reference (data-URL, base64, URL) is resolved.
   - HTML error pages are rejected.
4. **Encrypted documents.** The site does not return the document directly:
   one response carries `{data, success, token}` where `data` is the encrypted
   payload, and a follow-up (`GetDocKey`) carries `{iv, key, success}`. The
   scraper stores both and decrypts them using the page's own WebCrypto
   (`AES-GCM`, `AES-CBC`, `AES-CTR` are tried), then validates the plaintext
   with magic bytes before saving. Only the key material returned by the site
   for the user's own authenticated session is used - nothing is hardcoded,
   and no access control is bypassed.
5. Real browser **downloads** are also captured, and a follow-up fetch (using
   the page's own authenticated session) is used for references that need one.
6. When the window closes with nothing saved, a report listing every response
   seen during that window is appended to the diagnostics file so you can see
   which request carries the document.

## Recognised document responses

Classification is magic-byte based, with `Content-Type` as a fallback:

- `%PDF-`                -> `.pdf`
- PNG / JPEG / TIFF / GIF / BMP magic -> matching image extension
- unknown binary         -> only saved when a magic-byte match is found

PDFs are rejected unless `%PDF-` appears in the first 1024 bytes, so an error
page mislabelled as `application/pdf` is never written to the dataset.
Metadata/configuration endpoints such as `GetDoc/` (which return JSON) are never
saved as documents; they only contribute search criteria and references.


## Render fallback (JSON-only records)

Not every viewer has a file to sniff. On viewers where "View" returns **pure
JSON** and JavaScript draws the record table on screen, there is no PDF or
image anywhere in the traffic - the network pipeline correctly finds nothing,
because there is genuinely nothing there.

For that case a *render fallback* is hooked into `handle_response` alongside
(not instead of) the normal document detection:

1. A JSON response arrives whose URL contains a fragment from
   `RENDER_FALLBACK_URL_FRAGMENTS` in `scraper/config.py`.
2. Payloads this scraper already understands as documents (the encrypted
   `{data, token}` / `{key, iv}` exchange) are excluded, and payloads outside
   `RENDER_FALLBACK_MIN_JSON_BYTES`/`MAX_JSON_BYTES` are ignored.
3. A view window opens, the page is given `RENDER_FALLBACK_DELAY_SECONDS`
   (default 2.5s, optionally waiting for `networkidle`) to draw the record.
4. If no document was captured in the meantime, the page is rendered:
   `page.screenshot(full_page=True)` by default, or `page.pdf()` when
   `RENDER_FALLBACK_FORMAT = "pdf"` and the browser is running headless
   (`page.pdf()` is headless-only; the scraper falls back to a screenshot
   automatically).
5. The bytes go through the **same** `_save_document` pipeline as every other
   capture: dedup by SHA-256, delay, criteria merge, metadata row, hashing and
   post-save validation. A `RENDER` exchange line is written to the
   diagnostics file.

Each portal names this endpoint differently, so the fragments in
`scraper/config.py` are common guesses only. **After clicking "View" on a
JSON-only record, open `logs/document_network_debug.txt` and look for:**

```
JSON response in a view window did not match RENDER_FALLBACK_URL_FRAGMENTS: ...
- if this is the record call, add a distinctive fragment of its path to
RENDER_FALLBACK_URL_FRAGMENTS in scraper/config.py
```

If you see that line for the call that returns your record data, copy a
distinctive piece of its URL path into `RENDER_FALLBACK_URL_FRAGMENTS`.

Two honest limitations:

- A full-page screenshot is a raster image, not a searchable/official
  certified copy - fine for an archive or OCR dataset. Set
  `RENDER_FALLBACK_FORMAT = "pdf"` (headless) if you want selectable text.
- The fallback only captures what the user's own logged-in session can see,
  exactly as manually screenshotting each record would - stay within what you
  are authorised to pull.

## Selenium engine (real Chrome)

`--engine selenium` runs the same capture pipeline against an ordinary
installed Chrome/Edge instead of Playwright's bundled Chromium:

```powershell
python -m scraper --engine selenium
```

- Chrome is started through Selenium Manager (no manual chromedriver download).
- The profile lives in `.selenium-profile` by default and downloads in
  `data/downloads/`.
- `--engine selenium` is useful when the site misbehaves under Playwright's
  Chromium, or when you want the record seen in a real Chrome window.

How the capture works under Selenium: Selenium 4 no longer exposes
`WebDriver.add_cdp_listener`, so `scraper/selenium_runner.py` opens Chrome's
DevTools socket directly (the `debuggerAddress` from the capabilities), sends
`Network.enable`, and forwards every network event into the existing
`handle_response` pipeline. Responses are read back with
`Network.getResponseBody` **on that same connection**, because the body cache
belongs to the session that enabled the network domain. One-shot commands
(`Page.printToPDF`, `Page.captureScreenshot`) still go through
`driver.execute_cdp_cmd`. Targets are re-discovered every second, so a new tab
is picked up automatically.

Everything else - view windows, encrypted-envelope handling, dedup, criteria
merge, metadata rows, render fallback, diagnostics and post-save validation -
is shared with the Playwright engine.

## Network diagnostics (`logs/document_network_debug.txt`)


Every request/response observed by the scraper is appended to
`logs/document_network_debug.txt` in this form:

```
12:34:56 | POST     | https://.../eRecord_eSearch/GetDoc/ | status=200 | content-type=application/json | size=512 | post-fields=[fromyear=..., gatno=...]
```

- Log contents are limited to **METHOD, URL, STATUS, CONTENT-TYPE, SIZE and
  POST field names/values**.
- Query values and POST fields whose names look sensitive (`token`, `session`,
  `auth`, `password`, `otp`, `cookie`, ...) are replaced with `<redacted>`, and
  `__RequestVerificationToken` (and any `__`-prefixed field) is never logged.
- Cookies, `Authorization` headers, and session IDs are never read or written.
- If a **View** click produces no saved document, the file ends with a
  `VIEW WINDOW CLOSED - NO DOCUMENT WAS SAVED` block listing every response in
  that window (`METHOD | URL | STATUS | CONTENT-TYPE | SIZE`) so the carrier of
  the document bytes can be identified and the detection rules extended.

## Where documents are stored

- Files: `data/documents/00003_S123_1_OS77_H4_G9.pdf` (the `00003` prefix is
  the metadata row `id`; `<stem>` is built from the record's criteria - survey,
  old survey, hissa, gat - falling back to the website's `Filename` POST field
  and finally `document_<id>`). An existing file is never overwritten.
- Log: `logs/scraper.log` records every detected, skipped, duplicated, and saved
  document with timestamps.

## Metadata format (`data/metadata.csv`)

| Column            | Meaning                                                      |
|-------------------|--------------------------------------------------------------|
| `id`              | Sequential row id                                             |
| `survey_no`       | Survey number from the search form (if visible at capture)    |
| `hissa_no`        | Hissa number from the search form                             |
| `old_survey_no`   | Old survey number from the search form                        |
| `gat_no`          | Gat number from the search form                               |
| `from_year`       | From-year search field                                        |
| `to_year`         | To-year search field                                          |
| `source_url`      | The request URL that returned the document                    |
| `saved_filename`  | Filename inside `data/documents/`                             |
| `content_type`    | Response content type                                         |
| `downloaded_at`   | UTC timestamp of the download                                 |

## Duplicate detection

Every downloaded body is hashed with SHA-256. The digest is appended to
`data/downloaded_hashes.txt`. Before saving, the new digest is compared against
this registry (also against digests captured earlier in the same run), so the
exact same document is never written twice. A skipped duplicate is logged with a
warning rather than saved.

## Privacy

Authentication cookies, tokens, passwords, and OTP values are never written into
`metadata.csv`, `downloaded_hashes.txt`, the documents, or the log files.

## Extending to automated search later

The search fields already map to a reusable model:

- `scraper/models.py` -> `SearchCriteria` (`survey_no`, `hissa_no`,
  `old_survey_no`, `gat_no`, `from_year`, `to_year`).
- `scraper/network.py` -> request/response parsing and document detection.
- `scraper/storage.py` -> de-duplication and metadata persistence.

A future automated-search module can fill a `SearchCriteria`, submit the search
form like the browser does, and reuse the same `CaptureSession` / `storage`
pipeline. Manual mode remains the only implemented flow in this version.