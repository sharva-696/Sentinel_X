import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from backend.app.utils.crypto import compute_bytes_hashes
from backend.app.modules.analysis.validator import validate_file_size
from backend.app.modules.analysis.esp_parser import parse_esp_binary
from backend.app.modules.analysis.string_extractor import extract_strings_with_offsets, categorize_strings
from backend.app.modules.analysis.secret_scanner import scan_for_secrets
from backend.app.models.assessment import AssessmentRecord
from backend.app.models.finding import FindingRecord


def analyze_firmware_bytes(
    file_bytes: bytes,
    original_filename: str = "firmware.bin",
    assessment_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes a complete, offline, hardware-independent firmware assessment.
    Returns structured results including metadata, hashes, strings, and sanitized findings.
    """
    # 1. Validation
    validate_file_size(len(file_bytes))

    if not assessment_id:
        assessment_id = str(uuid.uuid4())

    created_at = datetime.now(timezone.utc)

    # 2. Hashing (derived from actual bytes)
    sha256, md5 = compute_bytes_hashes(file_bytes)

    # 3. Binary parsing & metadata extraction
    parsed_metadata = parse_esp_binary(file_bytes)

    # 4. Printable string extraction & categorization
    extracted_strings, string_meta = extract_strings_with_offsets(file_bytes, min_length=4, max_strings=5000)
    categorized_strings = categorize_strings(extracted_strings)

    # 5. Secret scanning & finding generation (with deduplication and masking)
    findings = scan_for_secrets(extracted_strings, file_bytes, assessment_id=assessment_id)

    # If partition table discovered missing OTA redundancy, generate partition finding
    if parsed_metadata.get("partitions"):
        parts = parsed_metadata["partitions"]
        has_ota = any(p.get("subtype") in ["ota_0", "ota_1"] for p in parts)
        if not has_ota and len(parts) > 1:
            findings.append({
                "id": str(uuid.uuid4()),
                "assessment_id": assessment_id,
                "rule_id": "SEC-PART-001",
                "title": "Missing OTA Redundancy in Partition Table",
                "category": "Partition Security",
                "severity": "Medium",
                "confidence": "High",
                "detection_method": "Partition Table Structure Inspection",
                "byte_offset": "0x008000" if parsed_metadata.get("image_type") == "FULL_FLASH_DUMP" else "0x000000",
                "additional_offsets": [],
                "section": "PARTITION_TABLE",
                "evidence_masked": f"Partitions defined: {', '.join(p['label'] for p in parts)}. No OTA update partitions found.",
                "raw_occurrences": 1,
                "rationale": "Without dual OTA partitions, firmware updates cannot be staged safely or rolled back if corrupt.",
                "false_positive_cases": "Factory-only devices with no network connection or remote update intent.",
                "remediation": "Define ota_0 and ota_1 app partitions with an otadata partition in partitions.csv.",
                "verification_limitations": "Structural analysis of partition table only.",
                "is_potential": True,
            })

    # 6. Summary aggregation
    summary = {
        "critical": sum(1 for f in findings if f["severity"] == "Critical"),
        "high": sum(1 for f in findings if f["severity"] == "High"),
        "medium": sum(1 for f in findings if f["severity"] == "Medium"),
        "low": sum(1 for f in findings if f["severity"] == "Low"),
        "informational": sum(1 for f in findings if f["severity"] == "Informational"),
        "total_unique": len(findings),
    }

    # Preliminary risk rating heuristic for Phase 2
    if summary["critical"] > 0 or summary["high"] >= 2:
        risk_rating = "High"
    elif summary["high"] > 0 or summary["medium"] >= 2:
        risk_rating = "Moderate"
    elif summary["medium"] > 0 or summary["low"] > 0:
        risk_rating = "Low"
    else:
        risk_rating = "Clean"

    completed_at = datetime.now(timezone.utc)

    return {
        "assessment_id": assessment_id,
        "filename": original_filename,
        "file_size_bytes": len(file_bytes),
        "sha256": sha256,
        "md5": md5,
        "image_type": parsed_metadata["image_type"],
        "parser_status": parsed_metadata["parser_status"],
        "parser_warnings": parsed_metadata["warnings"],
        "image_metadata": parsed_metadata,
        "strings_summary": string_meta,
        "categorized_strings": categorized_strings,
        "findings_summary": summary,
        "risk_rating": risk_rating,
        "findings": findings,
        "status": "COMPLETED",
        "created_at": created_at.isoformat(),
        "completed_at": completed_at.isoformat(),
    }


def persist_analysis_record(db: Session, analysis_result: Dict[str, Any]) -> AssessmentRecord:
    """
    Persists the assessment record and sanitized findings to SQLite.
    Never stores unredacted sensitive values.
    """
    assessment = AssessmentRecord(
        id=analysis_result["assessment_id"],
        filename=analysis_result["filename"],
        file_size_bytes=analysis_result["file_size_bytes"],
        sha256=analysis_result["sha256"],
        md5=analysis_result["md5"],
        image_type=analysis_result["image_type"],
        status=analysis_result["status"],
        risk_score=0,  # Full risk scoring calculation implemented in Phase 4
        risk_rating=analysis_result["risk_rating"],
        image_metadata=analysis_result["image_metadata"],
        created_at=datetime.fromisoformat(analysis_result["created_at"]),
        completed_at=datetime.fromisoformat(analysis_result["completed_at"]),
    )
    db.add(assessment)

    for f_data in analysis_result["findings"]:
        finding = FindingRecord(
            id=f_data["id"],
            assessment_id=analysis_result["assessment_id"],
            rule_id=f_data["rule_id"],
            title=f_data["title"],
            category=f_data["category"],
            severity=f_data["severity"],
            confidence=f_data["confidence"],
            detection_method=f_data["detection_method"],
            byte_offset=f_data.get("byte_offset"),
            additional_offsets=f_data.get("additional_offsets"),
            section=f_data.get("section"),
            evidence_masked=f_data["evidence_masked"],
            raw_occurrences=f_data.get("raw_occurrences", 1),
            rationale=f_data.get("rationale"),
            false_positive_cases=f_data.get("false_positive_cases"),
            remediation=f_data.get("remediation"),
            verification_limitations=f_data.get("verification_limitations"),
            is_potential=f_data.get("is_potential", True),
        )
        db.add(finding)

    db.commit()
    db.refresh(assessment)
    return assessment
