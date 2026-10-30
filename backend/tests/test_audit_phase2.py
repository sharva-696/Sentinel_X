import io
import json
import struct
import hashlib
import pytest
from fastapi.testclient import TestClient

from backend.app.modules.analysis import (
    analyze_firmware_bytes,
    parse_esp_binary,
    detect_image_type,
    calculate_risk_score,
)
from backend.app.models.assessment import AssessmentRecord
from backend.app.models.finding import FindingRecord
from backend.tests.test_analysis import create_synthetic_esp32_binary, create_synthetic_partition_table


# =========================================================================
# 1. Secret Redaction Comprehensive Canary Audit
# =========================================================================

def test_canary_secret_redaction_audit(client: TestClient, db_session):
    """
    Deliberately places recognizable synthetic canary secrets in firmware data,
    then rigorously searches all returned, serialized, and persisted data to
    guarantee that not a single canary value leaks in unredacted form.
    """
    canary_wifi_pass = "CANARY_WIFI_SECRET_XYZ999"
    canary_aws_key = "AKIA1111222233334444"
    canary_gh_token = "ghp_1234567890abcdef1234567890abcdef"
    canary_mqtt_pass = "CANARY_MQTT_PASS_123456"
    canary_pem_body = "CANARY_PRIVATE_KEY_MATERIAL_XYZ_987"
    canary_generic_pwd = "CANARY_GENERIC_PASSWORD_CONF_123"

    canaries = [
        canary_wifi_pass,
        canary_aws_key,
        canary_gh_token,
        canary_mqtt_pass,
        canary_pem_body,
        canary_generic_pwd,
    ]

    # Build payload with canary secrets
    payload = bytearray()
    payload.extend(b"\xe9\x01\x02\x20\x00\x00\x08\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    
    canary_string_block = (
        f"wifi_sta_pwd = '{canary_wifi_pass}'\x00"
        f"AWS_KEY: {canary_aws_key}\x00"
        f"GITHUB_TOKEN: {canary_gh_token}\x00"
        f"mqtt://admin:{canary_mqtt_pass}@broker.canary.net:1883\x00"
        f"password = '{canary_generic_pwd}'\x00"
        f"-----BEGIN RSA PRIVATE KEY-----\n{canary_pem_body}\n-----END RSA PRIVATE KEY-----\x00"
    ).encode("ascii")

    # Segment 1: DROM
    payload.extend(struct.pack("<II", 0x3F400000, len(canary_string_block)))
    payload.extend(canary_string_block)

    # 1. Run analysis directly
    result = analyze_firmware_bytes(bytes(payload), "canary_test.bin")
    result_json = json.dumps(result)

    # Check that NONE of the raw canaries appear in the returned JSON structure
    for canary in canaries:
        assert canary not in result_json, f"Raw canary leaked in analyze_firmware_bytes result: {canary}"

    # 2. Run analysis through HTTP API
    file_payload = {"file": ("canary_test.bin", io.BytesIO(bytes(payload)), "application/octet-stream")}
    response = client.post("/api/firmware/analyze", files=file_payload)
    assert response.status_code == 200
    api_text = response.text

    for canary in canaries:
        assert canary not in api_text, f"Raw canary leaked in /api/firmware/analyze response: {canary}"

    # 3. Check SQLite database persistence
    assessment_id = response.json()["assessment_id"]
    db_assessment = db_session.query(AssessmentRecord).filter(AssessmentRecord.id == assessment_id).first()
    assert db_assessment is not None

    for finding in db_assessment.findings:
        evidence = finding.evidence_masked
        for canary in canaries:
            assert canary not in evidence, f"Raw canary leaked in persisted FindingRecord: {canary}"

    # 4. Check assessment retrieval endpoint
    get_res = client.get(f"/api/firmware/{assessment_id}")
    assert get_res.status_code == 200
    get_text = get_res.text
    for canary in canaries:
        assert canary not in get_text, f"Raw canary leaked in /api/firmware/{assessment_id} endpoint: {canary}"


# =========================================================================
# 2. Firmware Classification & Ambiguity Tests
# =========================================================================

def test_classification_ambiguous_large_file_without_esp_structures():
    """A 2MB file with random bytes must be classified as RAW_BINARY, not FULL_FLASH_DUMP."""
    random_large = b"\x12\x34\x56\x78" * (512 * 1024)  # 2 MB
    assert detect_image_type(random_large) == "RAW_BINARY"


def test_classification_spurious_partition_magic_rejected():
    """A 2MB file with partition magic at 0x8000 but corrupt partition entries must NOT be classified as FULL_FLASH_DUMP."""
    fake_dump = bytearray(b"\x00" * (2 * 1024 * 1024))
    # Place magic at 0x8000 but fill with garbage (invalid partition type 0xFF)
    fake_dump[0x8000:0x8002] = b"\x50\xaa"  # 0xAA50
    fake_dump[0x8002] = 0xFF  # invalid partition type
    assert detect_image_type(bytes(fake_dump)) == "RAW_BINARY"


def test_classification_valid_full_flash_dump():
    """Constructs a genuine flash dump fixture with bootloader at 0x1000 and valid partition table at 0x8000."""
    dump = bytearray(b"\xff" * (2 * 1024 * 1024))  # 2 MB unprogrammed flash
    
    # Bootloader at 0x1000 (starts with 0xE9, entry 0x40080000)
    boot_hdr = bytearray(24)
    boot_hdr[0] = 0xE9
    boot_hdr[1] = 1
    struct.pack_into("<I", boot_hdr, 4, 0x40080000)
    dump[0x1000 : 0x1000 + 24] = boot_hdr

    # Partition table at 0x8000
    pt_data = create_synthetic_partition_table()
    dump[0x8000 : 0x8000 + len(pt_data)] = pt_data

    assert detect_image_type(bytes(dump)) == "FULL_FLASH_DUMP"


def test_classification_bootloader_vs_app_binary():
    """Bootloader has only IRAM/DRAM segments, while App binary has DROM/IROM flash segments."""
    # App binary (has DROM segment)
    app_bin = create_synthetic_esp32_binary()
    assert detect_image_type(app_bin) == "APP_BINARY"

    # Bootloader binary (only IRAM segment, small size)
    boot_bin = bytearray(24)
    boot_bin[0] = 0xE9
    boot_bin[1] = 1
    struct.pack_into("<I", boot_bin, 4, 0x40080000)
    # IRAM segment (0x40080000)
    seg_hdr = struct.pack("<II", 0x40080000, 32)
    boot_payload = bytes(boot_bin) + seg_hdr + (b"\x90" * 32)
    assert detect_image_type(boot_payload) == "BOOTLOADER_BINARY"


# =========================================================================
# 3. Binary Parser Boundary & Robustness Tests
# =========================================================================

def test_parser_boundary_truncated_headers():
    """Tests 1, 8, and 23-byte inputs (shorter than 24-byte minimum header)."""
    for size in [1, 8, 23]:
        data = b"\xe9" + (b"\x00" * (size - 1))
        parsed = parse_esp_binary(data)
        assert parsed["parser_status"] == "INSUFFICIENT_DATA"
        assert parsed["header_valid"] is False
        assert len(parsed["warnings"]) > 0


def test_parser_boundary_huge_segment_count():
    """Header specifies 255 segments, but file is truncated."""
    data = bytearray(24)
    data[0] = 0xE9
    data[1] = 255  # Exaggerated segment count
    struct.pack_into("<I", data, 4, 0x40080000)
    
    parsed = parse_esp_binary(bytes(data))
    assert parsed["header_valid"] is True
    assert parsed["parser_status"] == "PARTIAL"
    assert any("unusually large number" in w for w in parsed["warnings"])


def test_parser_boundary_segment_length_exceeds_file():
    """Segment length in header claims 10MB in a 100-byte file."""
    data = bytearray(24)
    data[0] = 0xE9
    data[1] = 1
    struct.pack_into("<I", data, 4, 0x40080000)
    # Segment header claims 10,000,000 bytes
    data.extend(struct.pack("<II", 0x40080000, 10_000_000))
    data.extend(b"\xaa" * 32)

    parsed = parse_esp_binary(bytes(data))
    assert parsed["header_valid"] is True
    assert parsed["parser_status"] == "PARTIAL"
    assert any("truncated" in w for w in parsed["warnings"])
    assert len(parsed["segments"]) == 1
    # Check that data_length was clipped safely to actual available bytes
    assert parsed["segments"][0]["data_length"] == 32


def test_parser_boundary_random_binary():
    """Random binary input must parse safely with parser_status UNRECOGNIZED."""
    random_data = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe" * 32
    parsed = parse_esp_binary(random_data)
    assert parsed["header_valid"] is False
    assert parsed["parser_status"] == "UNRECOGNIZED"


def test_parser_boundary_all_zero_and_all_ff():
    """All-zero and all-0xFF flash sectors parse safely without unhandled exceptions."""
    zeros = b"\x00" * 256
    parsed_zeros = parse_esp_binary(zeros)
    assert parsed_zeros["parser_status"] == "UNRECOGNIZED"

    ffs = b"\xff" * 256
    parsed_ffs = parse_esp_binary(ffs)
    assert parsed_ffs["parser_status"] == "UNRECOGNIZED"


# =========================================================================
# 4. Risk Scoring Determinism & Formula Audit
# =========================================================================

def test_risk_scorer_empty_findings():
    score, rating, breakdown = calculate_risk_score([])
    assert score == 0
    assert rating == "Clean"
    assert breakdown["capped_score"] == 0
    assert len(breakdown["rule_breakdown"]) == 0


def test_risk_scorer_single_critical_finding():
    finding = {
        "rule_id": "SEC-KEY-001",
        "title": "Private Key",
        "severity": "Critical",
        "confidence": "High",
        "raw_occurrences": 1,
    }
    score, rating, breakdown = calculate_risk_score([finding], enforce_severity_floor=False)
    # Critical weight = 10, Conf High = 1.0, 1 occurrence = 1.0 multiplier -> 10 pts
    assert score == 10
    assert rating == "Low"
    assert breakdown["rule_breakdown"][0]["calculated_points"] == 10.0


def test_risk_scorer_dampening_repetitive_findings():
    """Multiple occurrences of the same rule must be dampened to prevent score inflation."""
    finding_10_occurrences = {
        "rule_id": "SEC-WIFI-001",
        "title": "Wi-Fi Credential",
        "severity": "High",
        "confidence": "High",
        "raw_occurrences": 10,
    }
    score, rating, breakdown = calculate_risk_score([finding_10_occurrences], enforce_severity_floor=False)
    # High weight = 7, Conf High = 1.0
    # Dampening factor = 0.2, max dampening = 5 -> multiplier = 1 + (0.2 * 5) = 2.0
    # Expected points = 7 * 1.0 * 2.0 = 14.0 (NOT 7 * 10 = 70!)
    assert score == 14
    assert rating == "Low"
    assert breakdown["rule_breakdown"][0]["multiplier"] == 2.0
    assert breakdown["rule_breakdown"][0]["calculated_points"] == 14.0


def test_risk_scorer_composite_severity():
    """Checks composite scoring across multiple distinct rules."""
    findings = [
        {"rule_id": "SEC-KEY-001", "severity": "Critical", "confidence": "High", "raw_occurrences": 1},  # 10 pts
        {"rule_id": "SEC-CLOUD-001", "severity": "High", "confidence": "High", "raw_occurrences": 1},   # 7 pts
        {"rule_id": "SEC-NET-002", "severity": "Medium", "confidence": "Medium", "raw_occurrences": 1}, # 4 * 0.8 = 3.2 pts
        {"rule_id": "SEC-NET-001", "severity": "Low", "confidence": "Medium", "raw_occurrences": 1},    # 1 * 0.8 = 0.8 pts
    ]
    # Total = 10 + 7 + 3.2 + 0.8 = 21.0 pts
    score, rating, breakdown = calculate_risk_score(findings, enforce_severity_floor=False)
    assert score == 21
    assert rating == "Moderate"


def test_risk_scorer_severity_floors():
    """Verifies that High severity findings floor the score at >= 60 (High) and Critical at >= 80 (Critical)."""
    high_finding = {
        "rule_id": "SEC-PWD-001",
        "title": "Hardcoded Password",
        "severity": "High",
        "confidence": "Medium",
        "raw_occurrences": 1,
    }
    score, rating, breakdown = calculate_risk_score([high_finding])
    assert score >= 60
    assert rating == "High"
    assert breakdown["severity_floor_applied"] is True

    crit_finding = {
        "rule_id": "SEC-KEY-001",
        "title": "Private Key",
        "severity": "Critical",
        "confidence": "High",
        "raw_occurrences": 1,
    }
    crit_score, crit_rating, _ = calculate_risk_score([crit_finding])
    assert crit_score >= 80
    assert crit_rating == "Critical"



def test_risk_scorer_score_capped_at_100():
    """Scores above 100 must cap cleanly at 100 with Critical rating."""
    many_criticals = [
        {"rule_id": f"RULE_{i}", "severity": "Critical", "confidence": "High", "raw_occurrences": 5}
        for i in range(20)
    ]
    score, rating, breakdown = calculate_risk_score(many_criticals)
    assert score == 100
    assert rating == "Critical"
    assert breakdown["raw_score"] > 100.0
    assert breakdown["capped_score"] == 100


# =========================================================================
# 5. Persistence & API Integrity Tests
# =========================================================================

def test_api_unique_assessment_ids_across_requests(client: TestClient):
    esp_bin = create_synthetic_esp32_binary()
    file1 = {"file": ("app1.bin", io.BytesIO(esp_bin), "application/octet-stream")}
    file2 = {"file": ("app2.bin", io.BytesIO(esp_bin), "application/octet-stream")}

    res1 = client.post("/api/firmware/analyze", files=file1)
    res2 = client.post("/api/firmware/analyze", files=file2)

    assert res1.status_code == 200
    assert res2.status_code == 200

    id1 = res1.json()["assessment_id"]
    id2 = res2.json()["assessment_id"]

    assert id1 != id2
    assert len(id1) == 36
    assert len(id2) == 36


def test_api_nonexistent_assessment_returns_404(client: TestClient):
    res = client.get("/api/firmware/non-existent-uuid-000000")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_api_reveal_secrets_faculty_demo_mode(client: TestClient):
    """
    Verifies that secrets are masked by default across standard endpoints and downloadable reports,
    but can be revealed on demand via reveal_secrets=true for faculty demo presentations.
    """
    esp_bin = create_synthetic_esp32_binary()
    file_payload = {"file": ("demo_app.bin", io.BytesIO(esp_bin), "application/octet-stream")}
    res = client.post("/api/firmware/analyze", files=file_payload)
    assert res.status_code == 200
    assessment_id = res.json()["assessment_id"]

    # 1. Standard assessment GET: secrets MUST be masked
    std_res = client.get(f"/api/assessments/{assessment_id}")
    assert std_res.status_code == 200
    std_data = std_res.json()
    wifi_f = next(f for f in std_data["findings"] if f["rule_id"] == "SEC-WIFI-001")
    assert wifi_f["evidence"]["snippet_raw"] is None
    assert wifi_f["evidence"]["secret_token"] is None
    assert "SuperSecretWifiPass123" not in std_res.text

    # 2. Demo Mode assessment GET: raw secret and token are revealed
    demo_res = client.get(f"/api/assessments/{assessment_id}?reveal_secrets=true")
    assert demo_res.status_code == 200
    demo_data = demo_res.json()
    wifi_demo = next(f for f in demo_data["findings"] if f["rule_id"] == "SEC-WIFI-001")
    assert wifi_demo["evidence"]["snippet_raw"] is not None
    assert wifi_demo["evidence"]["secret_token"] == "SuperSecretWifiPass123"
    assert "SuperSecretWifiPass123" in demo_res.text

    # 3. Downloadable reports (HTML & PDF) MUST remain sanitized (no raw password)
    html_res = client.get(f"/api/assessments/{assessment_id}/report/html")
    assert html_res.status_code == 200
    assert "SuperSecretWifiPass123" not in html_res.text
    assert "wifi_password" in html_res.text  # masked present

    pdf_res = client.get(f"/api/assessments/{assessment_id}/report/pdf")
    assert pdf_res.status_code == 200
    assert b"SuperSecretWifiPass123" not in pdf_res.content

