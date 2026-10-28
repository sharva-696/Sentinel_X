# Sentinel-X Phase 5: Reporting Engine Specification & Verification

## 1. Overview

Phase 5 implements the Sentinel-X **Reporting Engine**, providing exportable, auditor-ready security assessment reports in both **HTML** and **PDF** formats.

The reporting engine adheres to the core defensive principles of Sentinel-X:
- **Single Canonical Source of Truth**: Both HTML and PDF generators consume data prepared by [`build_report_data()`](file:///home/sharva/Sentinel_X/backend/app/modules/reporting/data_loader.py#L30-L120), guaranteeing that report contents, metadata, finding counts, risk scores, and score breakdowns are strictly identical across formats.
- **Zero Raw Secret Leakage**: Multi-pass sanitization ensures raw credentials, API keys, private keys, and Wi-Fi passphrases never appear in HTML markup or PDF streams.
- **Strict Injection Defense**: All user-controlled metadata and firmware-derived strings are aggressively escaped (`html.escape` and `saxutils.escape`), protecting browsers against Cross-Site Scripting (XSS) and ReportLab against XML parsing errors.
- **Zero External Dependencies / Tracking**: HTML reports use self-contained CSS with zero remote stylesheets, fonts, or scripts. PDF reports execute entirely offline with zero network requests.
- **Defensive Integrity**: The report explicitly labels findings as *potential indicators*, details static methodology boundaries, and never invents hardware attributes for offline analyses.

---

## 2. Report Sections & Canonical Data Sources

Every generated report contains the following six core sections:

| Section | Description | Canonical Data Source |
| :--- | :--- | :--- |
| **A. Cover & Target Metadata** | Branding, Assessment ID, timestamps (UTC), target filename, file size, SHA-256 and MD5 hashes, detected image format, and optional serial-interrogated hardware specifications. | `AssessmentRecord` (id, filename, file_size_bytes, sha256, md5, image_type, created_at) and optional `DeviceRecord`. |
| **B. Executive Summary** | Composite Risk Score (0–100), standardized Risk Band (`Clean`, `Low`, `Moderate`, `High`, `Critical`), total unique findings, and severity distribution counts. | `AssessmentRecord.risk_score`, `AssessmentRecord.risk_rating`, and aggregated `FindingRecord`s. |
| **C. Assessment Methodology** | Explicit description of static analysis operations performed (ESP image header analysis, partition inspection, printable string extraction, regex scanning, Shannon entropy, deduplication, and risk scoring). Explicit non-claims (no dynamic execution, no hardware flashing). | Deterministic methodology documentation matched to `AssessmentRecord.image_type` and metadata. |
| **D. Detailed Findings** | Itemized security indicators: rule ID, category, severity badge, confidence level, primary offset, additional aggregated offsets, sanitized evidence snippet, security rationale, false-positive scenarios, and remediation guidance. | `FindingRecord`s (sorted by severity hierarchy: Critical &rarr; High &rarr; Medium &rarr; Low &rarr; Informational). |
| **E. Risk Score Breakdown** | Mathematical formula explanation, factor definitions (base weights, confidence multipliers, occurrence dampening factor), and itemized score contribution table. | Stored `AssessmentRecord.score_breakdown` (never recalculated). |
| **F. Limitations & Recommendations** | Technical boundaries of static analysis (encrypted binaries, obfuscation, offline hardware limits) and ESP32 defensive best practices (Flash Encryption, Secure Boot v2, NVS Encryption, dual OTA). | Standardized defensive hardening guidelines. |

---

## 3. Architecture & Rendering Implementation

### 3.1 Data Preparation Layer (`data_loader.py`)
- [`build_report_data(assessment)`](file:///home/sharva/Sentinel_X/backend/app/modules/reporting/data_loader.py): Transforms the SQLAlchemy `AssessmentRecord` into an immutable dictionary.
- Distinguishes offline assessments from hardware assessments: if `assessment.device` is `None`, `is_offline_analysis` is set to `True`, rendering an explicit offline advisory instead of fabricating hardware details.
- Sorts findings deterministically by severity ranking.

### 3.2 HTML Report Generation (`html_report.py`)
- Standalone HTML5 document with embedded high-contrast CSS.
- **Non-Reliance on Color Alone**: Severity badges use high-contrast text, clear category labels, and distinct structural borders.
- **Layout Safety**: Long evidence strings and disassembled snippets are enclosed in `<pre class="evidence-pre"><code>` blocks with horizontal scroll and `word-break: break-all`, preventing page blowout.
- **Print Optimization**: Includes `@media print` directives to suppress cards breaks (`page-break-inside: avoid`).

### 3.3 PDF Report Generation (`pdf_report.py`)
- Built using **ReportLab 5.1.0** Platypus flowable framework.
- **Two-Pass Numbered Canvas**: Implements [`NumberedCanvas`](file:///home/sharva/Sentinel_X/backend/app/modules/reporting/pdf_report.py#L32-L73) to compute the total page count dynamically, rendering `Page X of Y` in the footer and a running header across subsequent pages.
- **Table Flow & Clipping Prevention**: All table cell entries are wrapped in Flowable `Paragraph`s with fixed column widths (`colWidths`), enabling text wrapping without clipping.
- **Repeated Headers**: Multi-page tables (such as partition structures, findings, and score breakdowns) declare `repeatRows=1` so table headers persist across page splits.

---

## 4. Security & Sanitization Safeguards

1. **HTML Escaping**:
   - Every dynamic string inserted into HTML is escaped via `html.escape(str(val), quote=True)`.
   - Verified by test `test_html_report_escaping_xss_and_injection`: strings like `<script>alert("XSS")</script>` and `<img src=x onerror=...>` are transformed to harmless entities (`&lt;script&gt;`).
2. **ReportLab XML Escaping**:
   - Dynamic text inserted into ReportLab paragraphs is escaped via `xml.sax.saxutils.escape(str(val))`.
   - Verified by test `test_pdf_report_handles_xml_and_markup_safely`: prevents unclosed tags (`<unclosed>`, `&`) from breaking the PDF layout engine.
3. **Canary Credential Audit**:
   - Verified by test `test_canary_secret_redaction_in_html_and_pdf`: synthetic secret canaries (`CANARY_SECRET_SUPER_SECRET_987654`) present in source binaries are strictly masked and never appear anywhere in the generated HTML or extracted PDF text.
4. **Read-Only Guarantee**:
   - Report generation queries the database in read-only mode and creates zero side-effects or duplicate records.

---

## 5. REST API Endpoints

| Method | Endpoint | Response Media Type | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/assessments/{assessment_id}/report/html` | `text/html; charset=utf-8` | Download standalone HTML security report. |
| `GET` | `/api/assessments/{assessment_id}/report/pdf` | `application/pdf` | Download formatted PDF security report. |

### Headers & Download Behavior
- **Content-Disposition**: `attachment; filename="Sentinel-X_Assessment_{assessment_id}.html"` (or `.pdf`).
- **Cache-Control**: `no-cache, no-store, must-revalidate` (ensures fresh report generation without browser caching).
- **Identifier Validation**: `assessment_id` is validated against `^[a-zA-Z0-9_-]{1,64}$`. Directory traversal strings (`../`) return HTTP 400 or 404.

---

## 6. Verification Results

All 97 unit, security, and integration tests pass cleanly:

```bash
cd /home/sharva/Sentinel_X/backend && python3 -m pytest -v
```

```
============================== 97 passed in 0.65s ==============================
- tests/test_analysis.py: 17 passed
- tests/test_assessment_management.py: 21 passed
- tests/test_audit_phase2.py: 17 passed
- tests/test_crypto.py: 3 passed
- tests/test_hardware.py: 19 passed
- tests/test_health_and_db.py: 2 passed
- tests/test_masking.py: 5 passed
- tests/test_reporting.py: 13 passed (Phase 5 report tests)
```
