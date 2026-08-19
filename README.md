# Sensitive Data Scanner

A Spring Boot desktop application that scans local files and folders for
sensitive personal data (PII) — Aadhaar, PAN, Card Numbers, Passport,
Driving Licence, Voter ID, Bank Account, IFSC, UPI ID, Phone Number, and
Email — with a live web dashboard, validated detection (Luhn/Verhoeff
checksums), configurable scan scope, and exportable reports.

---

## Table of Contents

- [System Architecture](#system-architecture)
- [Scan Request Flow](#scan-request-flow)
- [Component Overview](#component-overview)
- [Detected PII Types](#detected-pii-types)
- [API Endpoints](#api-endpoints)
- [Configuration](#configuration-applicationyml)
- [Setup & Run](#setup--run)
- [Packaging as a Standalone .exe](#packaging-as-a-standalone-exe)
- [Data Storage](#data-storage)
- [Tech Stack](#tech-stack)

---

## System Architecture

<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/61bd9ab4-c4df-4b22-ad72-993cec47d9d0" />


## Scan Request Flow

<img width="1698" height="926" alt="image" src="https://github.com/user-attachments/assets/97d83c92-89c0-4fd7-b276-60a31a8a07f1" />


## Component Overview

### Web Layer
| Component | Responsibility |
|---|---|
| `DashboardController` | REST API for the dashboard: trigger scans, poll live status, fetch findings/history, download reports, list available PII types. |
| `ScanTriggerRequest` | Request DTO for `POST /api/scans/trigger` — target paths, enabled PII types, optional custom regex overrides per type, and scan options. |
| `ScanRunSummaryDto` | Response DTO summarizing a run (status, counts, timestamps, scan path) — never exposes raw findings, only aggregate counts, for the summary endpoints. |

### Scan Engine (`core` package)
| Component | Responsibility |
|---|---|
| `ScanOrchestrator` | The pipeline conductor. Coordinates walking, extraction, detection, validation, masking, risk classification, and report writing for a single scan run. Runs file processing concurrently via virtual threads, capped by a `Semaphore`. |
| `FileWalker` | Walks the filesystem from one or more root paths. Honors recursive/hidden-file/excluded-path/symlink options. Multiple roots (e.g. `C:\` and `D:\`) are walked concurrently on separate virtual threads. |
| `ScanOptions` | Immutable record of scan-time behavior overrides: recursive, include hidden files, exclude configured paths, follow symlinks, file type filters. |
| `ScanContext` | Per-run mutable accumulator: findings list, counters (scanned/skipped/errors), and performance timing data (extraction/detection/attribute-read nanos) used for the end-of-run performance log. |

### Extraction (`extractor` package)
| Component | Responsibility |
|---|---|
| `ExtractorFactory` | Returns the correct `TextExtractor` implementation based on file extension. |
| `TextExtractor` | Interface: `extractText(Path) throws IOException`. |
| `PdfTextExtractor` | PDFBox-based extraction (`Loader.loadPDF`). Text-layer PDFs only — no OCR for scanned images. |
| `DocxTextExtractor`, `XlsxTextExtractor` | Apache POI-based extraction for Word/Excel files. |
| `CsvTextExtractor`, `TxtTextExtractor` | Plain-text based extraction. |

### Detection (`detector` package)
| Component | Responsibility |
|---|---|
| `DetectorRegistry` | Auto-collects every Spring-managed `SensitiveDataDetector` bean via constructor injection — new detectors just need `@Component` + interface implementation, no manual registration. |
| `SensitiveDataDetector` | Interface: `getType()` + `detectCandidates(String text)` — returns raw regex matches, not yet validated. |
| 11 detector implementations | One per PII type (see [Detected PII Types](#detected-pii-types)). Each uses a regex tuned for that type's real-world format; Card Number specifically uses issuer-prefix-anchored patterns (Visa/Mastercard/Amex/Discover/Diners) rather than any bare digit run, to minimize false positives. |

### Validation (`validator` package)
| Component | Responsibility |
|---|---|
| `LuhnValidator` | Standard Luhn checksum — used to confirm Card Number candidates. |
| `AadhaarChecksumValidator` | Verhoeff checksum — used to confirm Aadhaar Number candidates. |
| *(other 9 types)* | Structural regex match only — no public checksum algorithm exists for these formats, so `ScanOrchestrator.isValid()` accepts them by default. |

### Post-processing
| Component | Responsibility |
|---|---|
| `DataMasker` | Masks a raw finding before it's ever stored or displayed — e.g. keeps last 4 digits for card-like numbers, masks the local part of email-shaped values (UPI ID / Email) while preserving the domain/handle. Raw unmasked values are never persisted. |
| `RiskClassifier` | Maps each `SensitiveDataType` to a `RiskLevel` (CRITICAL / MEDIUM / NORMAL) via a static lookup map. |
| `ReportWriterFactory` / `ReportGenerator` | Writes the full findings list for a completed run to disk (CSV by default, per `application.yml`). |

### State & Persistence (`dashboard` package)
| Component | Responsibility |
|---|---|
| `ScanResultsHolder` | In-memory registry of all scan runs (`ConcurrentHashMap` + ordered list). Tracks which runs are currently active (supports multiple concurrent scans — the dashboard shows the most recently started one as "current"). Persists a one-line summary per completed run to `scan-history.csv`, and restores history from that file on startup. |
| `ScanRunRecord` | Mutable state for a single run while it's in progress or completed: findings, counters, status, current file being processed. |
| `ScanRunStatus` | Enum: `RUNNING`, `COMPLETED`, `FAILED`. |

### Configuration
| Component | Responsibility |
|---|---|
| `AppProperties` | Binds `scanner.*` properties from `application.yml` — target drives, supported extensions, excluded paths/folder names, schedule cron, report format/output directory, concurrency. |
| `ScanScheduler` | Runs scheduled scans automatically per the configured cron expression. |

### Frontend (`static/`)
| File | Responsibility |
|---|---|
| `index.html` | Single-page dashboard: Scan Configuration, Scan Status, Scan Summary, Findings (searchable/filterable/paginated), Scan History, Detection Rules, Settings. |
| `dashboard.js` | Polls the backend every 2 seconds for live status/findings/history, handles scan triggering, client-side filtering/pagination, CSV export, folder-browse modal, and per-PII-type custom regex input. |
| `style.css` | All dashboard styling. |

---

## Detected PII Types

| Type | Format | Validation |
|---|---|---|
| Card Number | Issuer-prefix-anchored (Visa/Mastercard/Amex/Discover/Diners) or grouped `dddd-dddd-dddd-dddd` | Luhn checksum |
| Aadhaar Number | 12 digits, grouped in 4s, first digit 2-9 | Verhoeff checksum |
| PAN Number | `AAAAA9999A`, 4th letter restricted to real holder-type codes | Structural only |
| Passport Number | 1 letter + 7 digits | Structural only |
| Driving Licence | State + RTO + year + serial | Structural only |
| Voter ID (EPIC) | 3 letters + 7 digits | Structural only |
| Bank Account Number | 9-18 digits, contextual | Structural only |
| IFSC Code | 4 letters + `0` + 6 alphanumeric | Structural only |
| UPI ID | `identifier@handle` | Structural, checked against known PSP handles |
| Phone Number | 10 digits, starts 6-9 | Structural only |
| Email Address | Standard `local@domain` | Structural only |

Every type also supports an optional **custom regex override** per scan, submitted via the dashboard, which fully replaces that type's default detector for that run.

---

## API Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/scans/trigger` | Start a new scan (paths, PII types, custom patterns, scan options — all optional, defaults to full configured scan). |
| `GET` | `/api/scans/current` | Live status of the most recently started running scan (204 if none running). |
| `GET` | `/api/scans/current/findings` | Recent findings (up to 200) for the current/latest run. |
| `GET` | `/api/scans/history` | All scan runs, past and present. |
| `GET` | `/api/scans/data-types` | List of all supported PII type enum values (drives the frontend's PII selector). |
| `GET` | `/api/scans/{runId}/download` | Download the full report file for a completed run. |
| `GET` | `/api/scans/config` | Read-only view of current `application.yml` scanner settings. |
| `GET` | `/api/scans/browse` | Folder-browse listing, used by the frontend's "Browse" folder-picker modal. |

---

## Configuration (`application.yml`)

```yaml
scanner:
  target-drives:
    - C:\
  supported-extensions: [pdf, docx, xlsx, txt, csv]
  excluded-paths: [...]        # absolute paths never scanned
  excluded-folder-names: [...] # folder names skipped anywhere in the tree
  schedule-cron: "0 0 */6 * * *"
  concurrency: 0                # 0 = auto (4x CPU cores)
  report:
    output-directory: reports
    format: csv
```

---

## Setup & Run

### Prerequisites
- JDK 21+
- Maven (or use IntelliJ's bundled Maven if you don't have it installed globally)

### Build
```bash
mvn clean package
```
(Or via IntelliJ: Maven panel → Lifecycle → `clean`, then `package`.)

### Run
```bash
java -jar target/sensitive-data-scanner-0.1.0-SNAPSHOT.jar
```

Then open: http://localhost:8080

## Packaging as a Standalone .exe

Requires a full JDK with `jpackage` (JDK 14+, not a JRE-only install).

```bash
mkdir jpackage-input
cp target/sensitive-data-scanner-0.1.0-SNAPSHOT.jar jpackage-input/

jpackage --type app-image --input jpackage-input \
  --main-jar sensitive-data-scanner-0.1.0-SNAPSHOT.jar \
  --name SensitiveDataScanner --dest dist
```

The resulting `dist/SensitiveDataScanner/` folder (containing the `.exe`,
`app/`, and `runtime/`) is fully self-contained — no Java installation
needed on the machine it's shared with. Zip that folder to distribute it.

---

## Data Storage

No database, Redis, or caching layer is used.

- **While a scan runs:** all state (findings, counters, current file) lives
  purely in memory (`ConcurrentHashMap` + synchronized `List` in
  `ScanResultsHolder`) — this is what the live-polling dashboard reads.
- **On scan completion:** exactly one summary row is appended to
  `reports/scan-history.csv`, and the full findings list is written to a
  separate per-run report file.
- **On app restart:** `scan-history.csv` is read back into memory, restoring
  scan history across restarts.

---

## Tech Stack

- **Backend:** Spring Boot 3.3.2, Java 21+ (virtual threads for concurrent file processing)
- **Document parsing:** Apache PDFBox (PDF), Apache POI (DOCX/XLSX), Apache Commons CSV
- **Frontend:** Vanilla HTML/CSS/JS, no framework — polling-based live updates
- **Packaging:** Maven, `jpackage` for native distribution.
