# Sentinel-X Phase 4: Assessment Management, Finding Normalization, Deduplication & Risk Scoring

## 1. Overview

Phase 4 of Sentinel-X enhances the assessment lifecycle, establishing an evidence-based, deterministic pipeline for:
1. **Finding Normalization**: Enforcing strict type safety, canonical severity rankings (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), and standardized confidence ratings (`HIGH`, `MEDIUM`, `LOW`).
2. **Deterministic Deduplication**: Computing robust cryptographic SHA-256 fingerprints across rules and sanitized evidence, preventing noisy repetitive findings while aggregating occurrence offsets.
3. **Transparent Risk Scoring**: Re-scoring normalized, deduplicated findings using an explainable formula with occurrence dampening, producing an audited risk score (0–100) and risk rating band.
4. **Local SQLite Persistence & Migration**: Providing non-destructive schema auto-migration (`upgrade_db_schema`) for existing SQLite databases and cascading lifecycle management.
5. **Comprehensive REST APIs**: Exposing paginated assessment history, severity-filtered finding inspection, and safe artifact cleanup on assessment deletion.

---

## 2. Normalized Finding Data Model

All security indicators produced by scanner rules or heuristic checks pass through `backend/app/modules/assessment/normalizer.py`.

### Canonical Schema

```python
class NormalizedFinding(BaseModel):
    rule_id: str                      # e.g., "RULE-SEC-001"
    category: str                     # e.g., "API Key"
    description: str                  # Human-readable explanation
    severity: FindingSeverity         # CRITICAL (10), HIGH (7), MEDIUM (4), LOW (1), INFO (0)
    confidence: FindingConfidence     # HIGH (1.0), MEDIUM (0.8), LOW (0.5)
    byte_offset: int                  # Primary detection location (hex-formatted in UI)
    additional_offsets: List[int]     # Additional occurrences in the binary
    sanitized_evidence: str           # Sanitized context snippet (NO RAW SECRETS)
    remediation: str                  # Actionable mitigation steps
    fingerprint: str                  # Deterministic SHA-256 fingerprint
    is_potential: bool = True         # Always True (defensive non-claim indicator)
```

### Fingerprint Computation

To ensure reproducibility across scans and prevent duplicate entries in reports and databases, a canonical fingerprint is computed:

$$\text{Fingerprint} = \text{SHA-256}(\text{rule\_id} \,\|\, \text{"|"} \,\|\, \text{category} \,\|\, \text{"|"} \,\|\, \text{normalized\_sanitized\_evidence})$$

- Leading/trailing whitespace in evidence is stripped.
- Newlines and internal carriage returns are collapsed to single spaces.
- Byte offsets are **excluded** from the fingerprint calculation so that identical secrets repeated across multiple flash segments are recognized as the same finding while tracking all occurrence offsets.

---

## 3. Finding Deduplication Algorithm

When analysis engines identify strings or configuration markers, multiple instances of identical secrets or patterns may be flagged. Sentinel-X collapses duplicates into a single canonical finding while preserving full spatial evidence:

```
[Raw Findings Stream] 
       │
       ▼
 [Normalize & Validate Schema]
       │
       ▼
 [Compute SHA-256 Fingerprint]
       │
       ├──> Existing Fingerprint?
       │        ├──> YES: Merge byte_offset into additional_offsets (sorted, unique)
       │        │         Elevate confidence if duplicate has higher certainty
       │        └──> NO:  Initialize canonical finding entry
       ▼
[Deduplicated Findings List]
```

---

## 4. Explainable Risk Scoring Engine

Sentinel-X calculates an overall firmware security risk score (0 to 100) using a transparent, multi-factor formula that accounts for severity weights, confidence multipliers, and occurrence dampening.

### Mathematical Formulation

$$\text{Finding Score} = \text{Base Weight}(\text{Severity}) \times \text{Confidence Multiplier} \times \left(1 + 0.2 \times \min(N - 1, 5)\right)$$

$$\text{Firmware Risk Score} = \min\left(100, \; \text{round}\left(\sum_{i=1}^{k} \text{Finding Score}_i\right)\right)$$

### Factor Reference

| Severity | Base Weight | Confidence | Multiplier |
| :--- | :---: | :--- | :---: |
| **CRITICAL** | 10 | **HIGH** | 1.0 |
| **HIGH** | 7 | **MEDIUM** | 0.8 |
| **MEDIUM** | 4 | **LOW** | 0.5 |
| **LOW** | 1 | | |
| **INFO** | 0 | | |

### Risk Rating Bands

- **Clean**: Score = 0
- **Low**: Score = 1 – 19
- **Moderate**: Score = 20 – 49
- **High**: Score = 50 – 79
- **Critical**: Score = 80 – 100

---

## 5. Persistence & Schema Migration

### Database Tables

1. **`assessments`**: Stores top-level metadata, SHA-256/MD5 hashes, parsed image details, partition tables, overall risk score, risk rating, and `score_breakdown` (JSON).
2. **`findings`**: Stores normalized findings with foreign key `assessment_id` (cascading delete on assessment removal). Includes `fingerprint`, `byte_offset`, `additional_offsets` (JSON array), and `created_at`.
3. **`devices`**: Stores interrogated ESP32 hardware metadata.

### Non-Destructive Auto-Migration (`upgrade_db_schema`)

To maintain backwards compatibility without requiring third-party migration tools during offline assessments:
- `backend/app/database.py` executes `upgrade_db_schema()` on engine startup.
- Queries `PRAGMA table_info()` for existing columns.
- Safely issues `ALTER TABLE findings ADD COLUMN fingerprint VARCHAR(64)` and `ALTER TABLE assessments ADD COLUMN score_breakdown JSON` if absent.
- Creates indexes: `ix_findings_fingerprint` and `ix_findings_assessment_id`.

---

## 6. Assessment Management REST API

The backend exposes full CRUD and filtering operations for assessment records:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/assessments` | List past assessments with pagination (`limit`, `offset`) and sorting |
| `GET` | `/api/assessments/{id}` | Retrieve complete assessment details with embedded normalized findings |
| `GET` | `/api/assessments/{id}/findings` | Retrieve findings for an assessment with optional `severity` filter |
| `DELETE` | `/api/assessments/{id}` | Delete assessment, associated findings, and stored binary file from disk |

---

## 7. Verification & Test Suite

All Phase 4 functionality is covered by 13 dedicated unit and integration tests in `backend/tests/test_assessment_management.py`.

Total backend test suite: **76 passed tests** in **0.23 seconds**:
- Schema normalization & invalid value fallback (`test_normalize_finding_*`)
- Fingerprint reproducibility & whitespace normalization (`test_fingerprint_*`)
- Deduplication & offset aggregation (`test_deduplicate_*`)
- Idempotent upsert persistence (`test_persist_analysis_record_idempotent`)
- Pagination, severity filtering, and deletion lifecycle (`test_api_*`)
