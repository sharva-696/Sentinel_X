# Sentinel-X: ESP32 Implementation Specification

## 1. Project Overview

Sentinel-X is a defensive embedded-device security assessment platform. The first release focuses exclusively on ESP32 development boards and ESP32 firmware binaries.

The application combines hardware identification, firmware inspection, potential secret detection, security findings, risk assessment, and report generation in one interface.

## 2. Supported Scope

### Included

- ESP32-compatible serial port discovery.
- Supported chip identification.
- Retrieval of available device metadata.
- Firmware binary upload and validation.
- SHA-256 firmware hashing.
- Binary metadata and printable-string analysis.
- Potential secret detection.
- Rule-based security indicators.
- Evidence-backed findings.
- Transparent risk scoring.
- Local assessment history.
- HTML and PDF report generation.
- React dashboard and FastAPI backend.

### Excluded from Version 1

- ESP8266 and non-ESP32 platforms.
- Raspberry Pi and Linux device assessments.
- Router and camera assessments.
- SSH-based acquisition.
- Automatic network-wide scanning.
- BLE security assessment.
- Automatic exploitation.
- Secure Boot or Flash Encryption bypass.
- Firmware modification or flashing as part of normal assessment.
- Claims of complete firmware extraction on every board.
- Automatic CVE applicability claims without supporting evidence.

## 3. Functional Requirements

FR-01: Enumerate available serial ports.

FR-02: Allow the user to select a port and initiate a supported ESP32 identification operation.

FR-03: Display retrieved chip and device metadata, including unavailable fields.

FR-04: Allow the user to upload a firmware binary.

FR-05: Validate uploaded files and calculate their SHA-256 hashes.

FR-06: Analyze supported binary structures and extract printable strings.

FR-07: Identify potential secrets using configurable detection rules.

FR-08: Produce structured findings with severity, confidence, evidence, and remediation.

FR-09: Calculate a documented risk score.

FR-10: Store assessment history in SQLite.

FR-11: Generate downloadable HTML and PDF reports.

FR-12: Display assessment status, findings, and report availability in the dashboard.

FR-13: Provide actionable errors for unsupported hardware, missing dependencies, invalid files, and failed operations.

## 4. Non-Functional Requirements

- Modular, maintainable code.
- Input validation at API boundaries.
- Local-first processing.
- No external transmission of uploaded firmware by default.
- Safe handling of uploaded files.
- Responsive user interface.
- Unit tests for analysis and scoring logic.
- Hardware-independent tests for the core analysis workflow.
- Clear installation and troubleshooting documentation.

## 5. Finding Data Model

Each finding should include:

- Unique finding ID.
- Assessment ID.
- Rule ID.
- Finding title.
- Description.
- Severity: Critical, High, Medium, Low, or Informational.
- Confidence: Low, Medium, or High.
- Evidence summary.
- Evidence location or byte offset, when applicable.
- Detection method.
- Recommended remediation.
- Limitations and verification status.

A detected string must not automatically be labelled a confirmed vulnerability.

## 6. Risk Scoring

Use a documented, configurable scoring system.

One proposed starting model is:

- Critical: 10 points.
- High: 7 points.
- Medium: 4 points.
- Low: 1 point.
- Informational: 0 points.

Calculate a raw score by summing the points for unique findings. Cap the displayed score at 100.

Suggested display categories:

- 0: No detected risk indicators.
- 1–19: Low.
- 20–49: Moderate.
- 50–79: High.
- 80–100: Critical.

These thresholds are project-defined heuristics, not a standard security rating. A score of zero does not establish that a device is secure.

The implementation must avoid counting the same underlying issue repeatedly merely because several detection rules found related evidence.

## 7. API Design

Proposed endpoints:

GET /api/health

GET /api/device/ports

POST /api/device/identify

POST /api/firmware/upload

POST /api/analysis/{assessment_id}/run

GET /api/assessments

GET /api/assessments/{assessment_id}

GET /api/assessments/{assessment_id}/findings

GET /api/reports/{assessment_id}/html

GET /api/reports/{assessment_id}/pdf

Hardware operations must use explicit user actions and bounded timeouts.

## 8. Acceptance Criteria

- The application launches using documented commands.
- A compatible connected ESP32 can be identified through the supported interface.
- Unsupported or unavailable device information is reported honestly.
- A valid firmware file can be uploaded and hashed.
- An invalid file is rejected with a clear error.
- Analysis results are reproducible from the same input and rule configuration.
- Potential secrets are masked in normal report output.
- Risk scores can be traced to the underlying findings.
- Assessment history survives application restarts.
- HTML and PDF reports can be downloaded.
- The main analysis workflow can be tested without physical hardware.
- Automated tests pass.
- No hardware-destructive operation runs silently.

## 9. Future Extensions

Possible future additions include network discovery on authorized networks, component-based CVE matching, additional firmware-analysis engines, SBOM generation, and broader microcontroller support.

These features must not delay completion of the ESP32-only release.
