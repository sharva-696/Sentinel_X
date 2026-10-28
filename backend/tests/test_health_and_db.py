from backend.app.models.device import DeviceRecord
from backend.app.models.assessment import AssessmentRecord
from backend.app.models.finding import FindingRecord


def test_health_endpoint(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["healthy", "degraded"]
    assert data["app_name"] == "Sentinel-X"
    assert data["version"] == "1.0.0"
    assert data["database_connected"] is True
    assert "tools" in data
    assert data["tools"]["pyserial_available"] is True
    assert data["tools"]["esptool_available"] is True
    assert data["tools"]["reportlab_available"] is True


def test_database_models_crud(db_session):
    # 1. Create Device
    device = DeviceRecord(
        port="/dev/ttyUSB0",
        chip_family="ESP32-S3",
        chip_revision=1,
        mac_address="84:f7:03:a1:b2:c3",
        crystal_freq="40MHz",
        flash_size="8MB",
        sdk_version="UNAVAILABLE_VIA_BOOTLOADER",
    )
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)
    assert device.id is not None

    # 2. Create Assessment
    assessment = AssessmentRecord(
        id="test-uuid-1234",
        filename="firmware.bin",
        file_size_bytes=524288,
        sha256="4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        md5="9e107d9d372bb6826bd81d3542a419d6",
        image_type="APP_BINARY",
        status="UPLOADED",
        risk_score=0,
        risk_rating="Clean",
        device_id=device.id,
    )
    db_session.add(assessment)
    db_session.commit()
    db_session.refresh(assessment)
    assert assessment.id == "test-uuid-1234"

    # 3. Create Finding
    finding = FindingRecord(
        id="fnd-1234",
        assessment_id=assessment.id,
        rule_id="SEC-WIFI-001",
        title="Potential Hardcoded Wi-Fi Credentials",
        category="Hardcoded Secrets",
        severity="High",
        confidence="Medium",
        detection_method="Regex Pattern Matching",
        byte_offset="0x00010000",
        evidence_masked="SSID: MyNet | Pass: ********",
        raw_occurrences=1,
        remediation="Store in NVS",
        is_potential=True,
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)

    assert finding.id == "fnd-1234"
    assert len(assessment.findings) == 1
    assert assessment.findings[0].rule_id == "SEC-WIFI-001"
