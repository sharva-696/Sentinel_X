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
