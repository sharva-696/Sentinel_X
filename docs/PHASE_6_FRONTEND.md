# Sentinel-X Phase 6: Frontend Dashboard Specification & Integration Guide

## 1. Overview & Architectural Decisions

Phase 6 implements the Sentinel-X **Frontend Dashboard**, providing an accessible, responsive, and secure single-page interface for ESP32 firmware analysis, telemetry exploration, report downloading, and non-destructive serial-device discovery.

### Technology Choice: Native ES2022+ Modules & Standard Web APIs
- **Stack**: Semantic HTML5, Modern CSS3 with CSS Custom Properties, and Vanilla ES2022+ Native Modules (`<script type="module">`).
- **Rationale**:
  1. **Zero External Build Toolchain Fragility**: Eliminates heavy npm/Node dependencies, Webpack/Vite bundlers, and transpilations. The entire UI executes natively in all modern evergreen browsers (Chrome, Firefox, Safari, Edge).
  2. **Zero Runtime Network Requirement**: Air-gapped and 100% self-contained. Loads zero external CDN scripts, remote fonts, or telemetry trackers, ensuring total compliance with Sentinel-X's local-first privacy guarantee.
  3. **High Security**: Drastically reduces the JavaScript supply-chain attack surface. Uses native browser DOM APIs with strict `textContent` escaping on all dynamic findings to prevent Cross-Site Scripting (XSS).
  4. **Seamless Integration**: Hosted directly by FastAPI via `StaticFiles(directory="frontend", html=True)`. A single backend command serves both the REST API and the complete interactive GUI.

---

## 2. Directory Structure

```
frontend/
├── index.html                   # HTML5 application shell & accessibility landmarks
├── css/
│   └── styles.css               # Cybersecurity design system (slate/dark palette, responsive)
└── js/
    ├── api.js                   # Centralized API client targeting backend endpoints
    ├── state.js                 # Global observable application state & formatters
    ├── components/
    │   ├── nav.js               # Responsive navigation sidebar & live health status
    │   ├── overview.js          # Executive dashboard metrics & recent assessments table
    │   ├── analyze.js           # Drag-and-drop firmware scan & progress indicator
    │   ├── history.js           # Paginated assessment list, risk filters & delete modal
    │   ├── detail.js            # In-depth technical telemetry, findings explorer & exports
    │   └── devices.js           # Host serial port scanner & non-destructive ESP32 identifier
    └── app.js                   # Client-side router bootstrap & hashchange dispatcher
```

---

## 3. Supported Workflows & Pages

### A. Overview Dashboard (`#overview`)
- Fetches live metrics from `GET /api/assessments` and `GET /api/devices`.
- Displays metric cards: Total Assessments, Maximum Risk Score with rating band, High/Critical Findings, and Discovered ESP32 Hardware Targets.
- Lists the 5 most recent assessments with severity distributions and immediate links to technical details.
- Handles empty database states with an inviting "Upload Firmware" prompt.

### B. Firmware Analysis (`#analyze`)
- Drag-and-drop zone with native file picker for `.bin`, `.img`, `.dump`, and `.raw` binaries.
- Client-side pre-validation checks: file size limit (32 MB) and non-empty file rejection.
- Submits `multipart/form-data` to `POST /api/firmware/analyze`.
- Disables submit button during processing with an animated spinner to prevent duplicate submissions.
- Displays instant assessment summary cards with quick links to the full inspection view.

### C. Assessment History (`#history`)
- Complete historical record of all scans retrieved via `GET /api/assessments`.
- Filtering dropdown by Risk Band (`Critical`, `High`, `Moderate`, `Low`, `Clean`).
- Quick actions: "Inspect" and "Delete".
- **Safe Deletion Modal (Step 10)**: Triggers an accessible confirmation modal explicitly advising the user that the assessment, associated findings, and stored binary file will be permanently deleted before executing `DELETE /api/assessments/{id}`.

### D. Assessment Details & Findings Explorer (`#detail/{id}`)
- Technical telemetry: SHA-256 and MD5 hashes, image format, file size, timestamps, and partition tables.
- **Offline Scope Advisory**: Explicitly labels offline scans as offline firmware analyses and warns that hardware eFuses and physical UART states cannot be audited without hardware connection.
- **Findings Explorer**:
  - Filter pills: `All`, `Critical`, `High`, `Medium`, `Low`.
  - Client-side search box filtering titles, categories, rule IDs, and byte offsets in real time.
  - Safe evidence rendering: context snippets are injected via `pre.textContent = ...`, preventing script or markup execution.
  - Displays primary byte offset, additional aggregated offsets, security rationale, false-positive scenarios, remediation guidance, and verification limitations.
- **Explainable Score Breakdown**: Itemizes base weights, confidence factors, occurrences ($N$), occurrence multipliers, and calculated points.
- **Report Downloads**: Dedicated "Download HTML Report" and "Download PDF Report" actions linked to `/api/assessments/{id}/report/html` and `/pdf`.

### E. ESP32 Hardware & Serial Device Discovery (`#devices`)
- Scans host serial ports via `GET /api/devices/ports` without fixed port assumptions.
- Displays port device path (`/dev/ttyUSB0`), descriptions, hardware VID:PID, and Linux dialout permissions status.
- Non-destructive interrogation: allows selecting a port and triggering `POST /api/devices/identify` using read-only esptool operations (`chip-id`, `read-mac`, `flash-id`).
- Supports an optional Mock Emulation Mode for developing and testing without physical hardware.
- Displays verified chip model, MAC address, flash size, crystal frequency, and flash mode.
- Interrogated Hardware Registry: displays previously identified hardware from `GET /api/devices`.

---

## 4. Security & Accessibility Safeguards

1. **Strict DOM Text Injection**:
   - Firmware strings, evidence snippets, error messages, and filenames are rendered exclusively through `textContent` or `document.createTextNode()`.
   - Prevents stored Cross-Site Scripting (XSS) when auditing malicious firmware containing embedded `<script>` or `<svg onload=...>` tags.
2. **Path Traversal Defense**:
   - Assessment and report IDs passed in URLs are validated against `^[a-zA-Z0-9_-]{1,64}$`, rejecting traversal attacks (`../`).
3. **Double-Submission Prevention**:
   - File upload and device interrogation buttons are automatically disabled upon click, presenting loading spinners until completion.
4. **Accessible Design System**:
   - High-contrast color palette compliant with WCAG AA standards.
   - Severity is conveyed using both distinct colors and explicit bold text labels (`Critical`, `High`, `Medium`, `Low`, `Info`).
   - Semantic HTML elements (`<header>`, `<nav>`, `<main>`, `<aside>`) and ARIA live regions (`aria-live="polite"`).
   - Clear `:focus-visible` styling for full keyboard navigation.
   - "Skip to main content" link for screen readers.

---

## 5. Startup & Execution Instructions

### Unified Startup (Backend API + Interactive Dashboard)

Run the backend from the project root:

```bash
cd /home/sharva/Sentinel_X/backend
python3 -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

- **Interactive Dashboard GUI**: Open [http://127.0.0.1:8000/dashboard/](http://127.0.0.1:8000/dashboard/) in any modern web browser.
- **REST API Docs**: Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) (Swagger UI).
- **API Root**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)

### Alternative Standalone Static Web Server
If running the frontend independently:

```bash
cd /home/sharva/Sentinel_X/frontend
python3 -m http.server 3000
```
Open [http://127.0.0.1:3000/](http://127.0.0.1:3000/) (requires backend running on port 8000; CORS is pre-configured).

---

## 6. Verification & Test Suite

All 104 unit, security, integration, and frontend tests pass cleanly:

```bash
cd /home/sharva/Sentinel_X/backend && python3 -m pytest -v
```

```
============================= 104 passed in 0.75s ==============================
- tests/test_analysis.py: 17 passed
- tests/test_assessment_management.py: 21 passed
- tests/test_audit_phase2.py: 17 passed
- tests/test_crypto.py: 3 passed
- tests/test_frontend.py: 7 passed (Phase 6 frontend integration tests)
- tests/test_hardware.py: 19 passed
- tests/test_health_and_db.py: 2 passed
- tests/test_masking.py: 5 passed
- tests/test_reporting.py: 13 passed
```
