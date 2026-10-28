import io
import struct
import hashlib
import pytest
from fastapi.testclient import TestClient

from backend.app.modules.analysis import (
    validate_file_size,
    ValidationError,
    parse_esp_binary,
    detect_image_type,
    extract_strings_with_offsets,
    categorize_strings,
    scan_for_secrets,
    calculate_shannon_entropy,
    analyze_firmware_bytes,
)
from backend.app.config import settings
from backend.app.models.assessment import AssessmentRecord
from backend.app.models.finding import FindingRecord


def create_synthetic_esp32_binary() -> bytes:
    """
    Constructs a valid synthetic ESP32 application image binary:
    - Magic 0xE9
    - 2 segments
    - Flash mode DIO (0x02), 40MHz & 4MB (0x20)
    - Entry point 0x40080644
    - Extended header for ESP32 (Chip ID 0x0000)
    - Segment 1: DROM string data containing embedded test strings
    - Segment 2: IRAM code stub
    """
    # 24-byte ESP header
    hdr = bytearray(24)
    hdr[0] = 0xE9  # Magic
    hdr[1] = 2     # 2 segments
    hdr[2] = 0x02  # Flash mode DIO
    hdr[3] = 0x20  # 40MHz, 4MB
    struct.pack_into("<I", hdr, 4, 0x40080644)  # Entry point
    # Extended header chip ID (offset 12 = 0x0000)
    struct.pack_into("<H", hdr, 12, 0x0000)
    hdr[23] = 0x01  # Hash appended flag

    # Segment 1 payload (DROM with string artifacts)
    strings_payload = (
        b"ESP-IDF v4.4.3\x00"
        b"wifi_password = 'SuperSecretWifiPass123'\x00"
        b"AKIAIOSFODNN7TEST123\x00"
        b"http://api.insecure-iot-endpoint.com/telemetry\x00"
        b"mqtt://device_user:MqttSecretPassword99@broker.iot.net:1883\x00"
        b"ESP_LOGI(TAG, 'System boot complete');\x00"
    )
    seg1_addr = 0x3F400000  # DROM
    seg1_hdr = struct.pack("<II", seg1_addr, len(strings_payload))

    # Segment 2 payload (IRAM stub)
    code_payload = b"\x00\x11\x22\x33" * 16
    seg2_addr = 0x40080000  # IRAM
    seg2_hdr = struct.pack("<II", seg2_addr, len(code_payload))

    # Assemble binary
    binary = bytes(hdr) + seg1_hdr + strings_payload + seg2_hdr + code_payload
    return binary


def create_synthetic_partition_table() -> bytes:
    """Constructs a valid 32-byte partition table binary with factory app and nvs."""
    pt = bytearray()
    # Entry 1: nvs (type=0x01, subtype=0x02, offset=0x9000, size=0x6000, label='nvs')
    e1 = bytearray(32)
    struct.pack_into("<H", e1, 0, 0xAA50)
    e1[2] = 0x01  # data
    e1[3] = 0x02  # nvs
    struct.pack_into("<I", e1, 4, 0x9000)
    struct.pack_into("<I", e1, 8, 0x6000)
    e1[12:15] = b"nvs"
    pt.extend(e1)

    # Entry 2: factory app (type=0x00, subtype=0x00, offset=0x10000, size=0x100000, label='factory')
    e2 = bytearray(32)
    struct.pack_into("<H", e2, 0, 0xAA50)
    e2[2] = 0x00  # app
    e2[3] = 0x00  # factory
    struct.pack_into("<I", e2, 4, 0x10000)
    struct.pack_into("<I", e2, 8, 0x100000)
    e2[12:19] = b"factory"
    pt.extend(e2)

    return bytes(pt)


# =========================================================================
# 1. Validation Tests
# =========================================================================

def test_validation_empty_file():
    with pytest.raises(ValidationError, match="empty"):
        validate_file_size(0)


def test_validation_oversized_file():
    oversized = settings.max_upload_size_bytes + 1
    with pytest.raises(ValidationError, match="exceeds the maximum"):
        validate_file_size(oversized)


def test_validation_valid_size():
    # Should not raise
    validate_file_size(1024)
    validate_file_size(settings.max_upload_size_bytes)


# =========================================================================
# 2. Binary Parser & Format Identification Tests
# =========================================================================

def test_detect_image_types():
    esp_bin = create_synthetic_esp32_binary()
    assert detect_image_type(esp_bin) == "APP_BINARY"

    pt_bin = create_synthetic_partition_table()
    assert detect_image_type(pt_bin) == "PARTITION_TABLE"

    random_bin = b"\x7f\x45\x4c\x46\x01\x01\x01\x00" * 10  # ELF-like / non-ESP
    assert detect_image_type(random_bin) == "RAW_BINARY"


def test_parse_valid_esp_binary():
    data = create_synthetic_esp32_binary()
    parsed = parse_esp_binary(data)

    assert parsed["header_valid"] is True
    assert parsed["header_magic"] == "0xe9"
    assert parsed["segments_count"] == 2
    assert parsed["spi_mode"] == "DIO"
    assert parsed["spi_speed"] == "40MHz"
    assert parsed["spi_size"] == "4MB"
    assert parsed["entry_point"] == "0x40080644"
    assert parsed["chip_target"] == "ESP32"
    assert parsed["hash_appended"] is True
    assert len(parsed["segments"]) == 2
    assert parsed["segments"][0]["section"] == "DROM"
    assert parsed["segments"][1]["section"] == "IRAM"
    assert parsed["parser_status"] == "SUCCESS"
    assert len(parsed["warnings"]) == 0


def test_parse_truncated_esp_binary():
    # Only 20 bytes - shorter than 24-byte header
    short_data = b"\xe9\x02\x02\x20\x44\x06\x08\x40"
    parsed = parse_esp_binary(short_data)
    assert parsed["header_valid"] is False
    assert parsed["parser_status"] == "INSUFFICIENT_DATA"
    assert len(parsed["warnings"]) > 0

    # Valid header, but segment 1 header truncated
    valid_hdr_truncated = create_synthetic_esp32_binary()[:28]
    parsed_trunc = parse_esp_binary(valid_hdr_truncated)
    assert parsed_trunc["header_valid"] is True
    assert parsed_trunc["parser_status"] == "PARTIAL"
    assert any("truncated" in w for w in parsed_trunc["warnings"])


def test_parse_partition_table():
    pt_data = create_synthetic_partition_table()
    parsed = parse_esp_binary(pt_data)
    assert parsed["image_type"] == "PARTITION_TABLE"
    assert parsed["parser_status"] == "SUCCESS"
    assert len(parsed["partitions"]) == 2
    assert parsed["partitions"][0]["label"] == "nvs"
    assert parsed["partitions"][0]["subtype"] == "nvs"
    assert parsed["partitions"][1]["label"] == "factory"


# =========================================================================
# 3. String Extraction Tests
# =========================================================================

def test_string_extraction_and_offsets():
    data = b"\x00\x00\x00\x00Hello_ESP32_Forensics\x00\x00\x00123\x00SensitiveTokenData1234\x00"
    strings, meta = extract_strings_with_offsets(data, min_length=5, max_strings=100)

    values = [s["value"] for s in strings]
    assert "Hello_ESP32_Forensics" in values
    assert "SensitiveTokenData1234" in values
    assert "123" not in values  # filtered out by min_length=5

    # Check offset
    hello_item = next(s for s in strings if s["value"] == "Hello_ESP32_Forensics")
    assert hello_item["offset"] == "0x000004"
    assert hello_item["offset_dec"] == 4


def test_string_extraction_no_strings():
    zero_data = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08" * 20
    strings, meta = extract_strings_with_offsets(zero_data, min_length=4)
    assert len(strings) == 0
    assert meta["extracted_count"] == 0
    assert meta["is_truncated"] is False


def test_string_extraction_max_limit():
    # Generate 50 strings
    block = b"".join(f"String_{i:04d}\x00".encode("ascii") for i in range(50))
    strings, meta = extract_strings_with_offsets(block, min_length=4, max_strings=10)
    assert len(strings) == 10
    assert meta["is_truncated"] is True
    assert meta["total_detected_count"] == 50


# =========================================================================
# 4. Secret Scanning & Evidence Masking Tests
# =========================================================================

def test_secret_scanner_detection_and_masking():
    esp_bin = create_synthetic_esp32_binary()
    strings, _ = extract_strings_with_offsets(esp_bin)
    findings = scan_for_secrets(strings, esp_bin)

    rule_ids = [f["rule_id"] for f in findings]
    assert "SEC-WIFI-001" in rule_ids
    assert "SEC-CLOUD-001" in rule_ids
    assert "SEC-NET-001" in rule_ids
    assert "SEC-NET-002" in rule_ids

    # Critical: Check that no raw secret is present in evidence_masked
    wifi_f = next(f for f in findings if f["rule_id"] == "SEC-WIFI-001")
    assert "SuperSecretWifiPass123" not in wifi_f["evidence_masked"]
    assert "********************" in wifi_f["evidence_masked"]

    aws_f = next(f for f in findings if f["rule_id"] == "SEC-CLOUD-001")
    assert "AKIAIOSFODNN7TEST123" not in aws_f["evidence_masked"]
    assert "AKIA" in aws_f["evidence_masked"]

    mqtt_f = next(f for f in findings if f["rule_id"] == "SEC-NET-002")
    assert "MqttSecretPassword99" not in mqtt_f["evidence_masked"]


def test_pem_private_key_detection():
    pem_key = (
        b"\x00" * 32
        + b"-----BEGIN RSA PRIVATE KEY-----\n"
        + b"MIIEowIBAAKCAQEA0Z3v9xMTESTTESTTEST...\n"
        + b"-----END RSA PRIVATE KEY-----\n"
    )
    strings, _ = extract_strings_with_offsets(pem_key)
    findings = scan_for_secrets(strings, pem_key)

    key_f = next((f for f in findings if f["rule_id"] == "SEC-KEY-001"), None)
    assert key_f is not None
    assert key_f["severity"] == "Critical"
    assert "MIIEowIBAAKCAQEA0Z3v9xMTESTTESTTEST" not in key_f["evidence_masked"]
    assert "[REDACTED PRIVATE KEY MATERIAL]" in key_f["evidence_masked"]


def test_shannon_entropy_calculation():
    low_entropy = "AAAAAAAAAAAA"
    high_entropy = "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb0"
    assert calculate_shannon_entropy(low_entropy) == 0.0
    assert calculate_shannon_entropy(high_entropy) > 3.0


# =========================================================================
# 5. Full Engine & API Integration Tests
# =========================================================================

def test_analyze_firmware_bytes_engine():
    esp_bin = create_synthetic_esp32_binary()
    result = analyze_firmware_bytes(esp_bin, original_filename="esp32_synthetic_app.bin")

    assert result["status"] == "COMPLETED"
    assert result["image_type"] == "APP_BINARY"
    assert result["file_size_bytes"] == len(esp_bin)
    assert result["sha256"] == hashlib.sha256(esp_bin).hexdigest()
    assert result["md5"] == hashlib.md5(esp_bin).hexdigest()
    assert result["findings_summary"]["total_unique"] > 0
    assert result["risk_rating"] in ["Moderate", "High", "Critical"]


def test_api_firmware_analyze_endpoint(client: TestClient):
    esp_bin = create_synthetic_esp32_binary()
    file_payload = {"file": ("esp32_app.bin", io.BytesIO(esp_bin), "application/octet-stream")}

    response = client.post("/api/firmware/analyze", files=file_payload)
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "COMPLETED"
    assert data["filename"] == "esp32_app.bin"
    assert data["image_type"] == "APP_BINARY"
    assert data["sha256"] == hashlib.sha256(esp_bin).hexdigest()
    assert "findings" in data
    assert len(data["findings"]) > 0

    # Ensure no raw secret is exposed in the JSON response
    response_text = response.text
    assert "SuperSecretWifiPass123" not in response_text
    assert "AKIAIOSFODNN7TEST123" not in response_text
    assert "MqttSecretPassword99" not in response_text

    # Verify database persistence via GET endpoint
    assessment_id = data["assessment_id"]
    get_res = client.get(f"/api/firmware/{assessment_id}")
    assert get_res.status_code == 200
    get_data = get_res.json()
    assert get_data["assessment_id"] == assessment_id
    assert get_data["findings_count"] == len(data["findings"])


def test_api_firmware_analyze_empty_file_rejected(client: TestClient):
    file_payload = {"file": ("empty.bin", io.BytesIO(b""), "application/octet-stream")}
    response = client.post("/api/firmware/analyze", files=file_payload)
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_api_firmware_upload_endpoint(client: TestClient):
    esp_bin = create_synthetic_esp32_binary()
    file_payload = {"file": ("upload_test.bin", io.BytesIO(esp_bin), "application/octet-stream")}

    response = client.post("/api/firmware/upload", files=file_payload)
    assert response.status_code == 201
    data = response.json()

    assert data["filename"] == "upload_test.bin"
    assert data["file_size_bytes"] == len(esp_bin)
    assert data["sha256"] == hashlib.sha256(esp_bin).hexdigest()
    assert data["detected_image_type"] == "APP_BINARY"
