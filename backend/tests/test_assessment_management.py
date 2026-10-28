import io
import uuid
import struct
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.modules.assessment import (
    FindingSeverity,
    FindingConfidence,
    compute_finding_fingerprint,
    normalize_finding,
    deduplicate_findings,
    NormalizedFinding,
)
from backend.app.modules.analysis.risk_scorer import calculate_risk_score
from backend.app.modules.analysis.engine import analyze_firmware_bytes, persist_analysis_record
from backend.app.models.assessment import AssessmentRecord
from backend.app.models.finding import FindingRecord
from backend.tests.test_analysis import create_synthetic_esp32_binary


# =========================================================================
# 1. Finding Normalization Tests
# =========================================================================

def test_normalize_finding_valid():
    raw = {
        "rule_id": "SEC-WIFI-001",
        "title": "Hardcoded Wi-Fi Password",
        "category": "Network Credentials",
        "severity": "High",
        "confidence": "Medium",
        "detection_method": "Regex",
        "byte_offset": "0x000100",
        "evidence_masked": "wifi_password = '*****************'",
        "raw_occurrences": 1,
    }
    normalized = normalize_finding(raw, "assess-123")
    assert normalized.rule_id == "SEC-WIFI-001"
    assert normalized.severity == FindingSeverity.HIGH
    assert normalized.confidence == FindingConfidence.MEDIUM
    assert normalized.byte_offset == "0x000100"
    assert len(normalized.fingerprint) == 64
    assert normalized.evidence_masked == "wifi_password = '*****************'"


def test_normalize_finding_invalid_severity_and_confidence_defaults():
    """Invalid or unknown severity defaults safely to LOW, and confidence to MEDIUM."""
    raw = {
        "rule_id": "SEC-CUSTOM-001",
        "severity": "UNKNOWN_SEVERITY_XYZ",
        "confidence": "UNKNOWN_CONFIDENCE_XYZ",
        "evidence_masked": "some_test_data",
    }
    normalized = normalize_finding(raw, "assess-123")
    assert normalized.severity == FindingSeverity.LOW
    assert normalized.confidence == FindingConfidence.MEDIUM


def test_fingerprint_determinism_and_whitespace_normalization():
    fp1 = compute_finding_fingerprint("SEC-WIFI-001", "Network", "SSID: TestNet | Pass: ******")
    fp2 = compute_finding_fingerprint("SEC-WIFI-001", "Network", "SSID:  TestNet  |  Pass:  ******")
    assert fp1 == fp2  # Normalized whitespace yields identical fingerprint

    fp3 = compute_finding_fingerprint("SEC-WIFI-001", "Network", "SSID: OtherNet | Pass: ******")
    assert fp1 != fp3  # Distinct evidence yields distinct fingerprint


def test_distinct_rules_produce_distinct_fingerprints():
    fp_wifi = compute_finding_fingerprint("SEC-WIFI-001", "Credentials", "Matched Token")
    fp_cloud = compute_finding_fingerprint("SEC-CLOUD-001", "Credentials", "Matched Token")
    assert fp_wifi != fp_cloud


# =========================================================================
# 2. Deduplication Tests
# =========================================================================

def test_deduplicate_findings_exact_duplicates():
    raw1 = {
        "rule_id": "SEC-WIFI-001",
        "category": "Network",
        "title": "Wi-Fi Pass",
        "severity": "High",
        "confidence": "High",
        "detection_method": "Regex",
        "byte_offset": "0x000100",
        "evidence_masked": "wifi_pass = '******'",
        "raw_occurrences": 1,
    }
    raw2 = dict(raw1)
    raw2["raw_occurrences"] = 2

    n1 = normalize_finding(raw1, "assess-1")
    n2 = normalize_finding(raw2, "assess-1")

    deduped = deduplicate_findings([n1, n2])
    assert len(deduped) == 1
    assert deduped[0].raw_occurrences == 3
    assert deduped[0].byte_offset == "0x000100"


def test_deduplicate_findings_same_rule_different_offsets():
    """Identical secret at different offsets merges occurrences while preserving all offset locations."""
    n1 = normalize_finding({
        "rule_id": "SEC-WIFI-001",
        "category": "Network",
        "title": "Wi-Fi Pass",
        "severity": "High",
        "confidence": "High",
        "detection_method": "Regex",
        "byte_offset": "0x000100",
        "evidence_masked": "wifi_pass = '******'",
        "raw_occurrences": 1,
    }, "assess-1")

    n2 = normalize_finding({
        "rule_id": "SEC-WIFI-001",
        "category": "Network",
        "title": "Wi-Fi Pass",
        "severity": "High",
        "confidence": "High",
        "detection_method": "Regex",
        "byte_offset": "0x000250",
        "evidence_masked": "wifi_pass = '******'",
        "raw_occurrences": 1,
    }, "assess-1")

    deduped = deduplicate_findings([n1, n2])
    assert len(deduped) == 1
    assert deduped[0].raw_occurrences == 2
    assert deduped[0].byte_offset == "0x000100"
    assert "0x000250" in deduped[0].additional_offsets


def test_deduplicate_findings_preserves_distinct_rules():
    n_wifi = normalize_finding({
        "rule_id": "SEC-WIFI-001",
        "category": "Network",
        "title": "Wi-Fi Pass",
        "severity": "High",
        "confidence": "High",
        "detection_method": "Regex",
        "byte_offset": "0x000100",
        "evidence_masked": "wifi_pass = '******'",
    }, "assess-1")

    n_mqtt = normalize_finding({
        "rule_id": "SEC-NET-002",
        "category": "Insecure Protocols",
        "title": "Plaintext MQTT",
        "severity": "Medium",
        "confidence": "Medium",
        "detection_method": "URI Pattern",
        "byte_offset": "0x000100",
        "evidence_masked": "mqtt://admin:******@broker:1883",
    }, "assess-1")

    deduped = deduplicate_findings([n_wifi, n_mqtt])
    assert len(deduped) == 2
    rule_ids = [d.rule_id for d in deduped]
    assert "SEC-WIFI-001" in rule_ids
    assert "SEC-NET-002" in rule_ids


# =========================================================================
# 3. Idempotent Persistence Tests
# =========================================================================

def test_persist_analysis_record_idempotent(db_session):
    """
    Rerunning or persisting the same analysis_result multiple times must
    update the existing record without throwing Primary Key or Unique constraint errors.
    """
    esp_bin = create_synthetic_esp32_binary()
    fixed_id = str(uuid.uuid4())
    result1 = analyze_firmware_bytes(esp_bin, "sample.bin", assessment_id=fixed_id)

    # 1. First persistence
    rec1 = persist_analysis_record(db_session, result1)
    assert rec1.id == fixed_id
    count_findings1 = len(rec1.findings)
    assert count_findings1 > 0

    # 2. Second persistence with updated risk score or timestamp
    result2 = dict(result1)
    result2["risk_score"] = 42
    result2["risk_rating"] = "Moderate"
    rec2 = persist_analysis_record(db_session, result2)

    assert rec2.id == fixed_id
    assert rec2.risk_score == 42
    assert rec2.risk_rating == "Moderate"

    # Verify no duplicate AssessmentRecord exists in DB
    total_assessments = db_session.query(AssessmentRecord).filter(AssessmentRecord.id == fixed_id).count()
    assert total_assessments == 1

    # Verify no orphan or duplicated findings exist in DB
    total_findings = db_session.query(FindingRecord).filter(FindingRecord.assessment_id == fixed_id).count()
    assert total_findings == count_findings1


# =========================================================================
# 4. Assessment API Endpoints & Lifecycle Tests
# =========================================================================

def test_api_list_assessments_pagination_and_filtering(client: TestClient):
    # Upload and analyze two binaries to create assessment history
    esp_bin = create_synthetic_esp32_binary()
    client.post("/api/firmware/analyze", files={"file": ("test1.bin", io.BytesIO(esp_bin), "application/octet-stream")})
    client.post("/api/firmware/analyze", files={"file": ("test2.bin", io.BytesIO(esp_bin), "application/octet-stream")})

    # Test listing endpoint
    res = client.get("/api/assessments?skip=0&limit=10")
    assert res.status_code == 200
    data = res.json()
    assert data["total_assessments"] >= 2
    assert len(data["assessments"]) >= 2
    assert "findings_summary" in data["assessments"][0]

    # Test filtering by status
    res_filtered = client.get("/api/assessments?status=COMPLETED")
    assert res_filtered.status_code == 200
    assert all(a["status"] == "COMPLETED" for a in res_filtered.json()["assessments"])


def test_api_get_assessment_detail_with_findings(client: TestClient):
    esp_bin = create_synthetic_esp32_binary()
    upload_res = client.post("/api/firmware/analyze", files={"file": ("detail_test.bin", io.BytesIO(esp_bin), "application/octet-stream")})
    assert upload_res.status_code == 200
    assessment_id = upload_res.json()["assessment_id"]

    # Fetch detail
    res = client.get(f"/api/assessments/{assessment_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == assessment_id
    assert len(data["findings"]) > 0
    assert "score_breakdown" in data
    assert data["score_breakdown"] is not None
    assert "rule_breakdown" in data["score_breakdown"]

    # Check finding fields
    first_f = data["findings"][0]
    assert "id" in first_f
    assert "fingerprint" in first_f
    assert first_f["fingerprint"] is not None
    assert "evidence" in first_f
    assert "occurrences_count" in first_f["evidence"]


def test_api_get_assessment_findings_with_severity_filter(client: TestClient):
    esp_bin = create_synthetic_esp32_binary()
    upload_res = client.post("/api/firmware/analyze", files={"file": ("filter_test.bin", io.BytesIO(esp_bin), "application/octet-stream")})
    assessment_id = upload_res.json()["assessment_id"]

    # Query with severity filter = High
    res_high = client.get(f"/api/assessments/{assessment_id}/findings?severity=High")
    assert res_high.status_code == 200
    data = res_high.json()
    assert all(f["severity"] == "High" for f in data["findings"])

    # Query with non-existent severity
    res_none = client.get(f"/api/assessments/{assessment_id}/findings?severity=Informational")
    assert res_none.status_code == 200
    assert res_none.json()["total_findings"] == 0


def test_api_delete_assessment_lifecycle(client: TestClient):
    esp_bin = create_synthetic_esp32_binary()
    upload_res = client.post("/api/firmware/analyze", files={"file": ("to_delete.bin", io.BytesIO(esp_bin), "application/octet-stream")})
    assessment_id = upload_res.json()["assessment_id"]

    # Verify exists
    assert client.get(f"/api/assessments/{assessment_id}").status_code == 200

    # Delete
    del_res = client.delete(f"/api/assessments/{assessment_id}")
    assert del_res.status_code == 200
    assert del_res.json()["deleted"] is True

    # Verify 404 after deletion
    assert client.get(f"/api/assessments/{assessment_id}").status_code == 404


def test_api_delete_nonexistent_assessment_returns_404(client: TestClient):
    res = client.delete("/api/assessments/non-existent-uuid-12345")
    assert res.status_code == 404


# =========================================================================
# 5. Targeted Audits: Issues A, B, and C Verification
# =========================================================================

def test_distinct_secrets_same_placeholder_preserve_identity():
    """
    Issue A Safeguard:
    Multiple distinct secrets that sanitize to the exact same placeholder must NOT
    have identical fingerprints and must NOT be merged into a single finding.
    Raw secrets must NEVER appear in fingerprints or finding objects.
    """
    secret1 = "SecretAlpha123!"
    secret2 = "SecretBeta0012!"  # Same length (15 chars) so both sanitize to identical asterisks

    raw1 = {
        "rule_id": "SEC-WIFI-001",
        "category": "Network Credentials",
        "title": "Hardcoded Wi-Fi Password",
        "severity": "High",
        "confidence": "Medium",
        "detection_method": "Wi-Fi Pattern",
        "byte_offset": "0x001000",
        "evidence": f'wifi_password = "{secret1}"',
        "raw_occurrences": 1,
    }
    raw2 = {
        "rule_id": "SEC-WIFI-001",
        "category": "Network Credentials",
        "title": "Hardcoded Wi-Fi Password",
        "severity": "High",
        "confidence": "Medium",
        "detection_method": "Wi-Fi Pattern",
        "byte_offset": "0x002000",
        "evidence": f'wifi_password = "{secret2}"',
        "raw_occurrences": 1,
    }

    n1 = normalize_finding(raw1, "assess-abc")
    n2 = normalize_finding(raw2, "assess-abc")

    # 1. Evidence is sanitized identically to the exact same placeholder string
    assert n1.evidence_masked == n2.evidence_masked
    assert n1.evidence_masked == 'wifi_password = "***************"'

    # 2. But distinct secret identities produce distinct fingerprints
    assert n1.fingerprint != n2.fingerprint

    # 3. Neither fingerprint contains the raw secret text
    assert secret1 not in n1.fingerprint
    assert secret2 not in n2.fingerprint
    assert secret1 not in n1.evidence_masked
    assert secret2 not in n2.evidence_masked

    # 4. Deduplication preserves both findings as separate records
    deduped = deduplicate_findings([n1, n2])
    assert len(deduped) == 2
    offsets = {f.byte_offset for f in deduped}
    assert offsets == {"0x001000", "0x002000"}


def test_genuinely_equivalent_secrets_consolidate_offsets():
    """
    Issue A Safeguard:
    Genuinely identical secrets repeated across offsets MUST be consolidated into
    a single canonical finding with aggregated offsets.
    """
    same_secret = "IdenticalPass999!"

    raw1 = {
        "rule_id": "SEC-WIFI-001",
        "category": "Network Credentials",
        "title": "Wi-Fi Password",
        "severity": "High",
        "confidence": "Medium",
        "detection_method": "Wi-Fi Pattern",
        "byte_offset": "0x001000",
        "evidence": f'wifi_password = "{same_secret}"',
        "raw_occurrences": 1,
    }
    raw2 = {
        "rule_id": "SEC-WIFI-001",
        "category": "Network Credentials",
        "title": "Wi-Fi Password",
        "severity": "High",
        "confidence": "Medium",
        "detection_method": "Wi-Fi Pattern",
        "byte_offset": "0x004500",
        "evidence": f'wifi_password = "{same_secret}"',
        "raw_occurrences": 1,
    }

    n1 = normalize_finding(raw1, "assess-abc")
    n2 = normalize_finding(raw2, "assess-abc")

    # Genuinely equivalent detections produce identical fingerprints
    assert n1.fingerprint == n2.fingerprint

    # Deduplication collapses them into 1 record and aggregates offsets
    deduped = deduplicate_findings([n1, n2])
    assert len(deduped) == 1
    consolidated = deduped[0]
    assert consolidated.byte_offset == "0x001000"
    assert "0x004500" in consolidated.additional_offsets
    assert consolidated.raw_occurrences == 2


def test_confidence_not_elevated_by_duplicate_occurrences():
    """
    Issue A Safeguard:
    Finding the same pattern at multiple offsets must NEVER artificially elevate confidence.
    Confidence must remain tied solely to the detection rule's intrinsic certainty.
    """
    raw = {
        "rule_id": "SEC-CFG-001",
        "category": "Configuration Security",
        "title": "Debug Log Pattern",
        "severity": "Low",
        "confidence": "Low",
        "detection_method": "Regex",
        "byte_offset": "0x001000",
        "evidence_masked": "ESP_LOGD [REDACTED]",
        "raw_occurrences": 1,
    }
    findings = [
        normalize_finding({**raw, "byte_offset": f"0x{i:06x}"}, "assess-xyz")
        for i in range(10)
    ]

    deduped = deduplicate_findings(findings)
    assert len(deduped) == 1
    # Confidence remains strictly LOW, not elevated
    assert deduped[0].confidence == FindingConfidence.LOW
    assert deduped[0].raw_occurrences == 10
    assert len(deduped[0].additional_offsets) == 9


def test_risk_scoring_meaningful_n_and_dampening_tradeoff():
    """
    Issue B Safeguard:
    Verify that N represents occurrences of a specific finding across offsets,
    dampening prevents score explosion on repeated duplicate offsets, and distinct
    findings contribute independently to the score.
    """
    # 1. Single finding repeated at 10 offsets (N=10)
    finding_10_offsets = {
        "rule_id": "SEC-WIFI-001",
        "title": "Wi-Fi Password",
        "severity": "High",
        "confidence": "Medium",
        "raw_occurrences": 10,
    }
    score_single, rating_single, breakdown_single = calculate_risk_score([finding_10_offsets])
    # Base weight (High) = 7, Conf (Medium) = 0.8
    # N = 10 -> dampening multiplier = 1.0 + (0.2 * 5) = 2.0
    # Expected points = 7 * 0.8 * 2.0 = 11.2 -> rounded to 11
    assert score_single == 11
    assert rating_single == "Low"
    assert breakdown_single["capped_score"] == 11
    assert breakdown_single["finding_breakdown"][0]["occurrences"] == 10
    assert breakdown_single["finding_breakdown"][0]["multiplier"] == 2.0

    # 2. Two distinct findings with 1 occurrence each (N=1 each)
    distinct_finding_1 = {
        "rule_id": "SEC-WIFI-001",
        "title": "Wi-Fi Password Net1",
        "severity": "High",
        "confidence": "Medium",
        "raw_occurrences": 1,
    }
    distinct_finding_2 = {
        "rule_id": "SEC-WIFI-001",
        "title": "Wi-Fi Password Net2",
        "severity": "High",
        "confidence": "Medium",
        "raw_occurrences": 1,
    }
    score_two, rating_two, breakdown_two = calculate_risk_score([distinct_finding_1, distinct_finding_2])
    # Each: 7 * 0.8 * 1.0 = 5.6 -> Total = 5.6 + 5.6 = 11.2 -> rounded to 11
    assert score_two == 11
    assert len(breakdown_two["finding_breakdown"]) == 2
    assert breakdown_two["finding_breakdown"][0]["calculated_points"] == 5.6
    assert breakdown_two["finding_breakdown"][1]["calculated_points"] == 5.6

    # 3. Empty findings list producing exactly 0 score and "Clean" band
    score_empty, rating_empty, breakdown_empty = calculate_risk_score([])
    assert score_empty == 0
    assert rating_empty == "Clean"
    assert len(breakdown_empty["finding_breakdown"]) == 0


def test_database_schema_upgrade_idempotent(db_session):
    """
    Issue C Safeguard:
    upgrade_db_schema() must be safe and idempotent across repeated invocations.
    """
    from backend.app.database import upgrade_db_schema
    # Running multiple times must succeed without throwing SQLite syntax or duplicate column errors
    for _ in range(3):
        upgrade_db_schema()


def test_sqlite_cascading_deletion_enforced(db_session):
    """
    Issue C Safeguard:
    Verify that SQLite foreign-key enforcement and cascading deletion remove
    all associated findings when an AssessmentRecord is deleted.
    """
    assess_id = f"cascade-test-{uuid.uuid4().hex[:8]}"
    assessment = AssessmentRecord(
        id=assess_id,
        filename="test_cascade.bin",
        file_size_bytes=1024,
        sha256="abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd",
        md5="1234567890abcdef1234567890abcdef",
        image_type="APP_BINARY",
        status="COMPLETED",
        risk_score=10,
        risk_rating="Low",
    )
    db_session.add(assessment)
    db_session.commit()

    # Add 2 findings for this assessment
    f1 = FindingRecord(
        id=str(uuid.uuid4()),
        assessment_id=assess_id,
        rule_id="RULE-1",
        title="Indicator 1",
        category="General",
        severity="Low",
        confidence="Medium",
        detection_method="Static",
        evidence_masked="test evidence 1",
        fingerprint=f"fp-1-{uuid.uuid4().hex}",
    )
    f2 = FindingRecord(
        id=str(uuid.uuid4()),
        assessment_id=assess_id,
        rule_id="RULE-2",
        title="Indicator 2",
        category="General",
        severity="Low",
        confidence="Medium",
        detection_method="Static",
        evidence_masked="test evidence 2",
        fingerprint=f"fp-2-{uuid.uuid4().hex}",
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    # Verify findings exist in database
    assert db_session.query(FindingRecord).filter(FindingRecord.assessment_id == assess_id).count() == 2

    # Delete the parent assessment
    db_session.delete(assessment)
    db_session.commit()

    # Verify cascading deletion removed both findings
    remaining_findings = db_session.query(FindingRecord).filter(FindingRecord.assessment_id == assess_id).count()
    assert remaining_findings == 0


def test_api_delete_assessment_path_traversal_rejected(client: TestClient):
    """
    Issue C Safeguard:
    Path traversal strings in assessment deletion must be rejected with HTTP 400 or 404,
    and must never touch or delete files outside UPLOADS_DIR.
    """
    malicious_ids = [
        "../../etc/passwd",
        "../shadow",
        "uploads/../../root",
        "valid_id/../secret",
    ]
    for bad_id in malicious_ids:
        res = client.delete(f"/api/assessments/{bad_id}")
        assert res.status_code in [400, 404]


def test_api_delete_assessment_handles_missing_file_cleanly(client: TestClient, db_session):
    """
    Issue C Safeguard:
    If the database record exists but the physical binary file is absent,
    deletion must succeed cleanly and report file_removed=False without misleading errors.
    """
    test_id = f"missingfile-{uuid.uuid4().hex[:8]}"
    assessment = AssessmentRecord(
        id=test_id,
        filename="nofile.bin",
        file_size_bytes=512,
        sha256="0000000000000000000000000000000000000000000000000000000000000000",
        md5="00000000000000000000000000000000",
        image_type="APP_BINARY",
        status="COMPLETED",
        risk_score=0,
        risk_rating="Clean",
    )
    db_session.add(assessment)
    db_session.commit()

    res = client.delete(f"/api/assessments/{test_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["deleted"] is True
    assert data["assessment_id"] == test_id
    assert data["file_removed"] is False
