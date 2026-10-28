# Sentinel-X Phase 4: Assessment Management, Finding Normalization, Deduplication & Risk Scoring

## 1. Overview

Phase 4 of Sentinel-X establishes an audited, deterministic, and safe assessment management lifecycle:
1. **Finding Normalization**: Enforces strict schema validation, canonical severity levels (`Critical`, `High`, `Medium`, `Low`, `Informational`), and confidence ratings (`High`, `Medium`, `Low`).
2. **Discriminatory Cryptographic Fingerprinting (Issue A Resolution)**: Computes deterministic SHA-256 fingerprints incorporating an `identity_hash` discriminator. Preserves distinct findings even when raw values sanitize to identical placeholders (e.g. multiple distinct Wi-Fi passwords), while guaranteeing zero raw credentials in fingerprints or API responses.
3. **Offset Aggregation & Confidence Safeguard**: Consolidates genuinely equivalent findings into a single canonical record with aggregated spatial offsets (`additional_offsets`). Prohibits artificial confidence elevation based on occurrence counts.
4. **Explainable Risk Scoring Engine (Issue B Resolution)**: Clearly defines $N$ as the number of byte-offset occurrences of a specific finding ($1 + \text{len}(\text{additional\_offsets})$). Applies occurrence dampening to bounded intervals ($1.0\times$ to $2.0\times$) to prevent duplicate string inflation, while allowing distinct vulnerabilities to contribute additively. Guarantees bounded scores ($0$–$100$) and a deterministic breakdown.
5. **Database Upgrades & Filesystem Deletion Safety (Issue C Resolution)**: Provides idempotent startup migrations (`upgrade_db_schema`), enables SQLite connection-level foreign keys (`PRAGMA foreign_keys = ON`) with cascading deletes, and enforces strict path-traversal validation confining artifact deletion strictly to `storage/uploads/`.

---

## 2. Normalized Finding Representation & Fingerprinting (Issue A)

All security indicators produced by scanner rules or heuristic checks pass through `backend/app/modules/assessment/normalizer.py`.

### Canonical Schema

```python
class NormalizedFinding(BaseModel):
    id: str                           # UUIDv4
    assessment_id: str                # UUIDv4 foreign key
    rule_id: str                      # e.g., "SEC-WIFI-001"
    title: str                        # Human-readable title
    category: str                     # e.g., "Network Credentials"
    severity: FindingSeverity         # Critical (10), High (7), Medium (4), Low (1), Informational (0)
    confidence: FindingConfidence     # High (1.0), Medium (0.8), Low (0.5)
    detection_method: str             # e.g., "Wi-Fi Configuration Pattern Matching"
    byte_offset: Optional[str]        # Primary detection offset (e.g. "0x001000")
    additional_offsets: List[str]     # Consolidated occurrences (e.g. ["0x004500", ...])
    section: Optional[str]            # Flash section (DROM, IROM, etc.)
    evidence_masked: str              # Masked context snippet (NO RAW CREDENTIALS)
    raw_occurrences: int              # Total occurrences (N = 1 + len(additional_offsets))
    identity_hash: Optional[str]      # 16-character SHA-256 digest of underlying secret
    fingerprint: str                  # 64-character SHA-256 stable fingerprint
    rationale: Optional[str]          # Threat context & impact explanation
    false_positive_cases: Optional[str]
    remediation: Optional[str]        # Actionable defensive fix guidance
    verification_limitations: Optional[str]
    is_potential: bool = True         # Always True (defensive indicator)
    created_at: datetime
```

### Deterministic Fingerprint Formula

To prevent distinct secrets from collapsing into one finding when sanitized to identical placeholders (e.g. `wifi_password = "***************"`), the fingerprint calculation incorporates a one-way `identity_hash`:

$$\text{Content} = \text{rule\_id} \,\|\, \text{"|"} \,\|\, \text{category} \,\|\, \text{"|"} \,\|\, \text{normalized\_evidence} \,\|\, \text{"|"} \,\|\, \text{identity\_hash}$$

$$\text{Fingerprint} = \text{SHA-256}(\text{Content})$$

#### Safeguards:
- **Zero Raw Secrets**: `identity_hash` is a one-way 16-hex-character digest of the matched token (`sha256(secret)[:16]`). Raw credentials are never stored in the database or exposed in the fingerprint.
- **Distinction Preservation**: Two different Wi-Fi passwords with identical lengths and formatting produce distinct `identity_hash` digests, producing distinct fingerprints. They remain separate findings.
- **Genuine Consolidation**: When the exact same secret appears across multiple flash sectors or partitions, its `identity_hash` matches identically. It is consolidated into one canonical finding, and all observed offsets are compiled into `additional_offsets`.
- **Confidence Integrity**: Multiple offset occurrences of the same finding never elevate confidence. Confidence is strictly bounded by the detection rule's intrinsic certainty.

---

## 3. Explainable Risk Scoring Engine (Issue B)

Sentinel-X calculates an overall firmware security risk score ($0$ to $100$) using an explainable formula.

### Definition of $N$ and Scoring Policy

- **Definition of $N$**:
  $$N = \text{raw\_occurrences} = 1 + \text{len}(\text{additional\_offsets})$$
  $N$ explicitly denotes **the number of byte-offset occurrences of that specific canonical finding across the firmware binary**.
- **Occurrence Dampening Trade-off**:
  If the exact same secret is repeated 10 times in flash (e.g., duplicated across partitions or compiler data tables), multiplying risk by 10 would produce massive artificial score inflation for a single vulnerability.
  Sentinel-X dampens multiple occurrences of the same finding using diminishing returns:
  $$\text{Occurrence Multiplier}(N) = 1.0 + \text{dampening\_factor} \times \min(N - 1, \; \text{max\_dampening\_instances})$$
  With default configuration ($\text{dampening\_factor} = 0.2$, $\text{max\_instances} = 5$):
  - $N = 1 \implies 1.0\times$ (no dampening)
  - $N = 2 \implies 1.2\times$
  - $N \ge 6 \implies 2.0\times$ (capped)
- **Distinct Finding Representation**:
  Distinct findings (different fingerprints, e.g. two separate Wi-Fi passwords or a Wi-Fi password and an AWS key) represent separate exposures and contribute independently and additively to the score.

### Point Formula & Rating Bands

$$\text{Points}(f) = \text{Base Weight}(\text{Severity}(f)) \times \text{Confidence Multiplier}(\text{Confidence}(f)) \times \text{Occurrence Multiplier}(N(f))$$

$$\text{Composite Risk Score} = \min\left(100, \; \text{round}\left(\sum_{f \in \text{Findings}} \text{Points}(f)\right)\right)$$

| Severity | Base Weight | Confidence | Multiplier | Rating Band | Score Range |
| :--- | :---: | :--- | :---: | :--- | :---: |
| **Critical** | 10 | **High** | 1.0 | **Clean** | 0 |
| **High** | 7 | **Medium** | 0.8 | **Low** | 1 – 19 |
| **Medium** | 4 | **Low** | 0.5 | **Moderate** | 20 – 49 |
| **Low** | 1 | | | **High** | 50 – 79 |
| **Informational** | 0 | | | **Critical** | 80 – 100 |

- **Empty Assessments**: An artifact with zero findings returns $\text{Score} = 0$, Rating = `"Clean"`, and an empty breakdown list.
- **Score Breakdown**: Returns `findings_evaluated_count`, `raw_score`, `capped_score`, `rating`, and an itemized list with `rule_id`, `title`, `severity`, `confidence`, occurrences $N$, `base_weight`, `confidence_factor`, `multiplier`, and `calculated_points`.

---

## 4. Database Upgrades & Filesystem Deletion Safety (Issue C)

### 1. SQLite Foreign-Key Enforcement & Cascading Deletion
- In SQLite, foreign-key constraints are disabled by default. Sentinel-X registers an engine-level event listener (`@event.listens_for(Engine, "connect")`) that issues `PRAGMA foreign_keys=ON;` on every database connection.
- `FindingRecord.assessment_id` declares `ForeignKey("assessments.id", ondelete="CASCADE")`.
- When an `AssessmentRecord` is deleted, all associated `FindingRecord`s are automatically pruned at the SQLite database layer.

### 2. Schema Upgrade Idempotence (`upgrade_db_schema`)
- Executed automatically at application startup.
- Queries `PRAGMA table_info()` prior to altering tables.
- Issues non-destructive `ALTER TABLE` operations only if columns (`fingerprint`, `created_at`, `score_breakdown`) are absent.
- Creates indexes safely using `CREATE INDEX IF NOT EXISTS`.
- Verified safe across repeated startups and re-invocations.

### 3. Path-Traversal Safe File Deletion (`get_safe_assessment_file_path`)
- Deleting an assessment removes both database records and uploaded binary files.
- To prevent path traversal attacks or malicious escapes (e.g. `../../etc/shadow` or directory deletion):
  1. `assessment_id` is strictly validated against `^[a-zA-Z0-9_-]{1,64}$`.
  2. The candidate path `(UPLOADS_DIR / f"{assessment_id}.bin").resolve()` is resolved.
  3. Path containment is verified via `candidate_path.relative_to(UPLOADS_DIR.resolve())` and `candidate_path.parent == UPLOADS_DIR.resolve()`.
  4. Symlinks are explicitly disallowed.
  5. Any traversal attempt is rejected with HTTP 400 Bad Request before database operations begin.

### 4. Transactional Integrity & Accurate Status Reporting
- The database deletion is executed inside an atomic transaction with explicit `try... db.rollback()`.
- If the database commit fails, an HTTP 500 is returned, and no file is touched. The system never reports a false success.
- If the database commit succeeds, the stored binary is unlinked. If the file is missing or file unlinking fails, the response accurately reports `file_removed: False` and the specific warning, preventing misleading state reporting.

---

## 5. Verification & Test Suite

All Phase 4 functionality and targeted audits are verified by **84 automated backend tests** running in **0.25 seconds** (100% passing):

```
============================== 84 passed in 0.25s ==============================
- tests/test_analysis.py: 17 passed
- tests/test_assessment_management.py: 21 passed (Phase 4 core & audits)
- tests/test_audit_phase2.py: 17 passed
- tests/test_crypto.py: 3 passed
- tests/test_hardware.py: 19 passed
- tests/test_health_and_db.py: 2 passed
- tests/test_masking.py: 5 passed
```
