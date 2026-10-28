import io
import uuid
import pytest
import pypdf
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.models.assessment import AssessmentRecord
from backend.app.models.finding import FindingRecord
from backend.app.models.device import DeviceRecord
from backend.app.modules.reporting import (
    build_report_data,
    generate_html_report,
    generate_pdf_report,
)


@pytest.fixture
def sample_assessment(db_session):
    """Creates a sample persisted assessment with findings across multiple severities."""
    assess_id = f"assess-rep-{uuid.uuid4().hex[:8]}"
    assessment = AssessmentRecord(
        id=assess_id,
        filename="firmware_prod_v1.0.bin",
        file_size_bytes=1048576,
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        md5="d41d8cd98f00b204e9800998ecf8427e",
        image_type="APP_BINARY",
        status="COMPLETED",
        risk_score=25,
        risk_rating="Moderate",
        image_metadata={
            "image_type": "APP_BINARY",
            "partitions": [
                {"label": "nvs", "type": "data", "subtype": "nvs", "offset": 0x9000, "size_bytes": 0x6000, "flags": "None"},
                {"label": "factory", "type": "app", "subtype": "factory", "offset": 0x10000, "size_bytes": 0x100000, "flags": "None"},
            ]
        },
        score_breakdown={
            "raw_score": 25.2,
            "capped_score": 25,
            "rating": "Moderate",
            "finding_breakdown": [
                {
                    "rule_id": "SEC-KEY-001",
                    "title": "Private Cryptographic Key",
                    "severity": "Critical",
                    "confidence": "High",
                    "confidence_factor": 1.0,
                    "occurrences": 1,
                    "multiplier": 1.0,
                    "calculated_points": 10.0,
                },
                {
                    "rule_id": "SEC-WIFI-001",
                    "title": "Potential Hardcoded Wi-Fi",
                    "severity": "High",
                    "confidence": "Medium",
                    "confidence_factor": 0.8,
                    "occurrences": 3,
                    "multiplier": 1.4,
                    "calculated_points": 7.84,
                },
                {
                    "rule_id": "SEC-NET-002",
                    "title": "Plaintext MQTT Credentials",
                    "severity": "Medium",
                    "confidence": "Medium",
                    "confidence_factor": 0.8,
                    "occurrences": 1,
                    "multiplier": 1.0,
                    "calculated_points": 3.2,
                },
                {
                    "rule_id": "SEC-NET-001",
                    "title": "Plaintext HTTP Endpoint",
                    "severity": "Low",
                    "confidence": "Medium",
                    "confidence_factor": 0.8,
                    "occurrences": 1,
                    "multiplier": 1.0,
                    "calculated_points": 0.8,
                },
            ],
            "disclaimer": "The Sentinel-X Risk Score is a deterministic heuristic.",
        },
    )
    db_session.add(assessment)
    db_session.commit()

    f1 = FindingRecord(
        id=str(uuid.uuid4()),
        assessment_id=assess_id,
        rule_id="SEC-KEY-001",
        title="Private Cryptographic Key Material",
        category="Hardcoded Secrets",
        severity="Critical",
        confidence="High",
        detection_method="Regex PEM",
        byte_offset="0x001000",
        additional_offsets=[],
        section="DROM",
        evidence_masked="-----BEGIN PRIVATE KEY-----\n[REDACTED PRIVATE KEY]\n-----END PRIVATE KEY-----",
        raw_occurrences=1,
        fingerprint=f"fp-crit-{uuid.uuid4().hex}",
        rationale="Private key extraction allows device impersonation.",
        false_positive_cases="Public test certificates.",
        remediation="Store private key in hardware secure element or eFuse.",
        verification_limitations="Static match only.",
    )
    f2 = FindingRecord(
        id=str(uuid.uuid4()),
        assessment_id=assess_id,
        rule_id="SEC-WIFI-001",
        title="Potential Hardcoded Wi-Fi Credentials",
        category="Network Credentials",
        severity="High",
        confidence="Medium",
        detection_method="Regex Wi-Fi",
        byte_offset="0x002000",
        additional_offsets=["0x004000", "0x006000"],
        section="DROM",
        evidence_masked='wifi_password = "***************"',
        raw_occurrences=3,
        fingerprint=f"fp-wifi-{uuid.uuid4().hex}",
        rationale="Exposes local wireless network.",
        false_positive_cases="Template strings.",
        remediation="Use ESP-IDF WiFi Provisioning.",
        verification_limitations="Static regex.",
    )
    f3 = FindingRecord(
        id=str(uuid.uuid4()),
        assessment_id=assess_id,
        rule_id="SEC-NET-002",
        title="Plaintext MQTT Broker Credentials",
        category="Insecure Protocols",
        severity="Medium",
        confidence="Medium",
        detection_method="Regex MQTT",
        byte_offset="0x008000",
        additional_offsets=[],
        section="DROM",
        evidence_masked="mqtt://iot_user:[REDACTED]@broker.hivemq.com",
        raw_occurrences=1,
        fingerprint=f"fp-mqtt-{uuid.uuid4().hex}",
        rationale="Cleartext MQTT allows packet sniffing.",
        false_positive_cases="Loopback test endpoints.",
        remediation="Migrate to MQTTS over TLS (port 8883).",
        verification_limitations="Does not verify broker connectivity.",
    )
    f4 = FindingRecord(
        id=str(uuid.uuid4()),
        assessment_id=assess_id,
        rule_id="SEC-NET-001",
        title="Insecure Plaintext HTTP Endpoint",
        category="Insecure Protocols",
        severity="Low",
        confidence="Medium",
        detection_method="Regex URL",
        byte_offset="0x00A000",
        additional_offsets=[],
        section="DROM",
        evidence_masked="http://api.weather-station.org/v1/update",
        raw_occurrences=1,
        fingerprint=f"fp-http-{uuid.uuid4().hex}",
        rationale="Vulnerable to MITM inspection.",
        false_positive_cases="Captive portal URLs.",
        remediation="Enforce HTTPS.",
        verification_limitations="Does not verify reachability.",
    )

    db_session.add_all([f1, f2, f3, f4])
    db_session.commit()
    db_session.refresh(assessment)
    return assessment


# =========================================================================
# 1. Security & Redaction Tests
# =========================================================================

def test_html_report_escaping_xss_and_injection(db_session):
    """
    Verifies that malicious markup, script tags, and event handlers in
    filenames or evidence are strictly escaped in HTML output.
    """
    xss_id = f"xss-test-{uuid.uuid4().hex[:8]}"
    assessment = AssessmentRecord(
        id=xss_id,
        filename='<script>alert("XSS")</script>.bin',
        file_size_bytes=2048,
        sha256="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        md5="11112222333344445555666677778888",
        image_type="APP_BINARY",
        status="COMPLETED",
        risk_score=10,
        risk_rating="Low",
    )
    db_session.add(assessment)
    db_session.commit()

    finding = FindingRecord(
        id=str(uuid.uuid4()),
        assessment_id=xss_id,
        rule_id="SEC-TEST-001",
        title='Finding <img src=x onerror=alert(1)> Title',
        category="XSS Test",
        severity="High",
        confidence="High",
        detection_method="Regex",
        byte_offset="0x001000",
        evidence_masked='var payload = "<svg onload=alert(2)>";',
        fingerprint="fp-xss",
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(assessment)

    report_data = build_report_data(assessment)
    html_output = generate_html_report(report_data)

    # Raw script tags and onerror attributes must NOT exist unescaped
    assert '<script>alert("XSS")</script>' not in html_output
    assert '<img src=x onerror=alert(1)>' not in html_output
    assert '<svg onload=alert(2)>' not in html_output

    # Escaped representations MUST be present
    assert '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;' in html_output
    assert '&lt;img src=x onerror=alert(1)&gt;' in html_output
    assert '&lt;svg onload=alert(2)&gt;' in html_output


def test_pdf_report_handles_xml_and_markup_safely(db_session):
    """
    ReportLab's Paragraph parser interprets XML-like tags.
    Malicious or unusual markup in evidence must be safely escaped so PDF builds without error.
    """
    test_id = f"pdf-esc-{uuid.uuid4().hex[:8]}"
    assessment = AssessmentRecord(
        id=test_id,
        filename="markup_test.bin",
        file_size_bytes=4096,
        sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        md5="abcdef1234567890abcdef12345678",
        image_type="APP_BINARY",
        status="COMPLETED",
        risk_score=5,
        risk_rating="Low",
    )
    db_session.add(assessment)
    db_session.commit()

    f = FindingRecord(
        id=str(uuid.uuid4()),
        assessment_id=test_id,
        rule_id="SEC-XML-001",
        title="Unclosed <tag & Special Chars>",
        category="Test",
        severity="Medium",
        confidence="Medium",
        detection_method="Static",
        byte_offset="0x002000",
        evidence_masked="<xml_tag attr='test'> & \"special\" <unclosed>",
        fingerprint="fp-xml",
    )
    db_session.add(f)
    db_session.commit()
    db_session.refresh(assessment)

    report_data = build_report_data(assessment)
    pdf_bytes = generate_pdf_report(report_data)
    assert len(pdf_bytes) > 1000

    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    full_pdf_text = "".join(page.extract_text() for page in reader.pages)
    assert "Unclosed" in full_pdf_text
    assert "special" in full_pdf_text


def test_canary_secret_redaction_in_html_and_pdf(db_session):
    """
    Canary test: Inserts a unique recognizable secret string.
    Verifies that the raw secret is never present in the generated HTML or PDF.
    """
    canary_secret = "CANARY_SECRET_SUPER_SECRET_987654"
    test_id = f"canary-{uuid.uuid4().hex[:8]}"

    assessment = AssessmentRecord(
        id=test_id,
        filename="canary_firmware.bin",
        file_size_bytes=8192,
        sha256="9999999999999999999999999999999999999999999999999999999999999999",
        md5="99999999999999999999999999999999",
        image_type="APP_BINARY",
        status="COMPLETED",
        risk_score=7,
        risk_rating="Low",
    )
    db_session.add(assessment)
    db_session.commit()

    # The finding stored in DB is masked (as guaranteed by the analysis engine)
    f = FindingRecord(
        id=str(uuid.uuid4()),
        assessment_id=test_id,
        rule_id="SEC-WIFI-001",
        title="Wi-Fi Password",
        category="Network Credentials",
        severity="High",
        confidence="Medium",
        detection_method="Regex",
        byte_offset="0x001000",
        evidence_masked='wifi_password = "********************************"',
        fingerprint="fp-canary",
    )
    db_session.add(f)
    db_session.commit()
    db_session.refresh(assessment)

    report_data = build_report_data(assessment)
    html_output = generate_html_report(report_data)
    pdf_bytes = generate_pdf_report(report_data)

    # 1. Assert raw canary is completely absent from HTML
    assert canary_secret not in html_output

    # 2. Assert raw canary is completely absent from PDF
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    pdf_text = "".join(page.extract_text() for page in reader.pages)
    assert canary_secret not in pdf_text


# =========================================================================
# 2. Functional & Report Quality Tests
# =========================================================================

def test_html_report_generation(sample_assessment):
    """Verifies that the HTML report contains all required sections and data."""
    report_data = build_report_data(sample_assessment)
    html_doc = generate_html_report(report_data)

    assert "<!DOCTYPE html>" in html_doc
    assert "Sentinel-X" in html_doc
    assert sample_assessment.id in html_doc
    assert sample_assessment.filename in html_doc
    assert sample_assessment.sha256 in html_doc
    assert "Executive Summary" in html_doc
    assert "Assessment Methodology" in html_doc
    assert "Detailed Security Findings" in html_doc
    assert "Risk Score Methodology & Calculation" in html_doc
    assert "Limitations & Defensive Recommendations" in html_doc
    assert "Private Cryptographic Key Material" in html_doc
    assert "Potential Hardcoded Wi-Fi Credentials" in html_doc

    # Zero external tracking or external script tags
    assert "http://" not in html_doc.replace(
        "http://api.weather-station.org/v1/update", ""
    ).replace(
        "http://www.w3.org", ""
    )
    assert "<script" not in html_doc


def test_pdf_report_generation_and_page_structure(sample_assessment):
    """Verifies that the PDF report builds cleanly and has expected pages and content."""
    report_data = build_report_data(sample_assessment)
    pdf_bytes = generate_pdf_report(report_data)

    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF-")

    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    assert len(reader.pages) >= 1

    first_page_text = reader.pages[0].extract_text()
    assert "Sentinel-X" in first_page_text
    assert sample_assessment.filename in first_page_text

    # Extract all text across pages
    all_text = "".join(page.extract_text() for page in reader.pages)
    assert "Executive Summary" in all_text
    assert "Detailed Security Findings" in all_text
    assert "SEC-KEY-001" in all_text
    assert "Page 1 of" in all_text or "Page" in all_text


def test_empty_assessment_reports(db_session):
    """Tests report generation for a clean firmware with zero findings."""
    clean_id = f"clean-{uuid.uuid4().hex[:8]}"
    clean_assessment = AssessmentRecord(
        id=clean_id,
        filename="clean_firmware.bin",
        file_size_bytes=512000,
        sha256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        md5="ffffffffffffffffffffffffffffffff",
        image_type="APP_BINARY",
        status="COMPLETED",
        risk_score=0,
        risk_rating="Clean",
    )
    db_session.add(clean_assessment)
    db_session.commit()
    db_session.refresh(clean_assessment)

    report_data = build_report_data(clean_assessment)
    html_output = generate_html_report(report_data)
    pdf_bytes = generate_pdf_report(report_data)

    # HTML verification
    assert "No Static Security Indicators Detected" in html_output
    assert "Clean" in html_output

    # PDF verification
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    all_text = "".join(page.extract_text() for page in reader.pages)
    assert "No Static Indicators Detected" in all_text
    assert "Clean" in all_text


def test_hardware_device_association_in_reports(db_session):
    """Verifies that reports accurately display device specs only when hardware is associated."""
    dev = DeviceRecord(
        port="/dev/ttyUSB0",
        chip_family="ESP32-D0WD-V3",
        chip_revision=3,
        mac_address="24:0a:c4:01:02:03",
        flash_size="4MB",
        flash_vendor_id="0x20",
        flash_mode="DIO",
        flash_speed="40m",
        crystal_freq="40MHz",
        sdk_version="v5.1-dev",
    )
    db_session.add(dev)
    db_session.commit()

    assess_id = f"hw-assess-{uuid.uuid4().hex[:8]}"
    assessment = AssessmentRecord(
        id=assess_id,
        filename="device_dump.bin",
        file_size_bytes=4194304,
        sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        md5="1234567890abcdef1234567890abcdef",
        image_type="FULL_FLASH_DUMP",
        status="COMPLETED",
        risk_score=10,
        risk_rating="Low",
        device_id=dev.id,
    )
    db_session.add(assessment)
    db_session.commit()
    db_session.refresh(assessment)

    report_data = build_report_data(assessment)
    assert report_data["is_offline_analysis"] is False
    assert "ESP32-D0WD-V3" in report_data["device"]["chip_type"]

    html_output = generate_html_report(report_data)
    assert "ESP32-D0WD-V3" in html_output
    assert "24:0a:c4:01:02:03" in html_output

    pdf_bytes = generate_pdf_report(report_data)
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    pdf_text = "".join(page.extract_text() for page in reader.pages)
    assert "ESP32-D0WD-V3" in pdf_text
    assert "24:0a:c4:01:02:03" in pdf_text


def test_multi_page_pdf_overflow_and_headers(db_session):
    """
    Creates an assessment with 15 findings to verify multi-page handling,
    repeated table headers, and page numbers.
    """
    large_id = f"large-assess-{uuid.uuid4().hex[:8]}"
    assessment = AssessmentRecord(
        id=large_id,
        filename="enterprise_iot_firmware.bin",
        file_size_bytes=2097152,
        sha256="4444444444444444444444444444444444444444444444444444444444444444",
        md5="44444444444444444444444444444444",
        image_type="APP_BINARY",
        status="COMPLETED",
        risk_score=60,
        risk_rating="High",
    )
    db_session.add(assessment)
    db_session.commit()

    findings = []
    for i in range(15):
        f = FindingRecord(
            id=str(uuid.uuid4()),
            assessment_id=large_id,
            rule_id=f"SEC-RULE-{i:03d}",
            title=f"Sample Indicator Finding Number {i + 1}",
            category="Configuration Analysis",
            severity="Medium",
            confidence="High",
            detection_method="Regex Analysis",
            byte_offset=f"0x{i * 0x1000:06x}",
            additional_offsets=[f"0x{(i * 0x1000) + 0x200:06x}"],
            section="DROM",
            evidence_masked=f"config_var_{i} = '[REDACTED_SNIPPET_{i}]';",
            fingerprint=f"fp-large-{i}",
            rationale="Sample rationale string to populate finding card content.",
            remediation="Sample remediation guidance.",
        )
        findings.append(f)
    db_session.add_all(findings)
    db_session.commit()
    db_session.refresh(assessment)

    report_data = build_report_data(assessment)
    pdf_bytes = generate_pdf_report(report_data)

    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    # 15 findings should span multiple pages
    assert len(reader.pages) >= 3

    # Check for running headers on subsequent pages
    page2_text = reader.pages[1].extract_text()
    assert "Sentinel-X ESP32 Security Assessment Report" in page2_text


# =========================================================================
# 3. API Route Tests
# =========================================================================

def test_api_get_html_report(client: TestClient, sample_assessment):
    res = client.get(f"/api/assessments/{sample_assessment.id}/report/html")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "charset=utf-8" in res.headers["content-type"]
    assert f'filename="Sentinel-X_Assessment_{sample_assessment.id}.html"' in res.headers["content-disposition"]
    assert "<!DOCTYPE html>" in res.text
    assert sample_assessment.id in res.text


def test_api_get_pdf_report(client: TestClient, sample_assessment):
    res = client.get(f"/api/assessments/{sample_assessment.id}/report/pdf")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert f'filename="Sentinel-X_Assessment_{sample_assessment.id}.pdf"' in res.headers["content-disposition"]
    assert res.content.startswith(b"%PDF-")


def test_api_report_missing_assessment_returns_404(client: TestClient):
    res_html = client.get("/api/assessments/non-existent-uuid-12345/report/html")
    assert res_html.status_code == 404

    res_pdf = client.get("/api/assessments/non-existent-uuid-12345/report/pdf")
    assert res_pdf.status_code == 404


def test_api_report_invalid_id_returns_400(client: TestClient):
    bad_id = "../../../etc/shadow"
    res_html = client.get(f"/api/assessments/{bad_id}/report/html")
    assert res_html.status_code in [400, 404]

    res_pdf = client.get(f"/api/assessments/{bad_id}/report/pdf")
    assert res_pdf.status_code in [400, 404]


def test_report_generation_does_not_modify_database(db_session, sample_assessment):
    """Verifies that report generation is strictly read-only."""
    orig_findings_count = len(sample_assessment.findings)
    orig_score = sample_assessment.risk_score

    report_data = build_report_data(sample_assessment)
    _ = generate_html_report(report_data)
    _ = generate_pdf_report(report_data)

    db_session.refresh(sample_assessment)
    assert len(sample_assessment.findings) == orig_findings_count
    assert sample_assessment.risk_score == orig_score
