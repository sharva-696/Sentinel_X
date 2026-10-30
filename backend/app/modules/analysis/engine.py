import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session

from backend.app.utils.crypto import compute_bytes_hashes
from backend.app.modules.analysis.validator import validate_file_size
from backend.app.modules.analysis.esp_parser import parse_esp_binary
from backend.app.modules.analysis.string_extractor import extract_strings_with_offsets, categorize_strings
from backend.app.modules.analysis.secret_scanner import scan_for_secrets
from backend.app.modules.analysis.risk_scorer import calculate_risk_score
from backend.app.modules.assessment.normalizer import (
    normalize_finding,
    deduplicate_findings,
    NormalizedFinding,
)
from backend.app.models.assessment import AssessmentRecord
from backend.app.models.finding import FindingRecord


def analyze_firmware_bytes(
    file_bytes: bytes,
    original_filename: str = "firmware.bin",
    assessment_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes a complete, offline, hardware-independent firmware assessment.
    Performs binary parsing, string extraction, secret scanning, normalization,
    deterministic deduplication, explainable risk scoring, and evidence redaction.
    """
    # 1. Input Validation
    validate_file_size(len(file_bytes))

    if not assessment_id:
        assessment_id = str(uuid.uuid4())

    created_at = datetime.now(timezone.utc)

    # 2. Hashing (derived dynamically from actual bytes)
    sha256, md5 = compute_bytes_hashes(file_bytes)

    # 3. Binary parsing & metadata extraction
    parsed_metadata = parse_esp_binary(file_bytes)

    # 4. Printable string extraction & categorization (sanitized)
    extracted_strings, string_meta = extract_strings_with_offsets(file_bytes, min_length=4, max_strings=5000)
    categorized_strings = categorize_strings(extracted_strings)

    # 5. Secret scanning & initial raw finding generation
    raw_findings = scan_for_secrets(extracted_strings, file_bytes, assessment_id=assessment_id)

    # If partition table discovered missing OTA redundancy, add partition finding
    if parsed_metadata.get("partitions"):
        parts = parsed_metadata["partitions"]
        has_ota = any(p.get("subtype") in ["ota_0", "ota_1"] for p in parts)
        if not has_ota and len(parts) > 1:
            raw_findings.append({
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

    # 6. Normalize and Deduplicate Findings with stable fingerprints
    normalized_list = [normalize_finding(rf, assessment_id) for rf in raw_findings]
    deduped_findings: List[NormalizedFinding] = deduplicate_findings(normalized_list)

    # Cache raw secrets in memory keyed by assessment_id for authorized persistence
    _RAW_FINDINGS_REGISTRY[assessment_id] = {
        f.id: (f.evidence_raw, f.secret_token) for f in deduped_findings
    }

    # Export findings to dictionary representations (strictly sanitized by default for outward JSON)
    findings_dicts = [f.to_dict(include_raw=False) for f in deduped_findings]

    # 7. Explainable Risk Score calculation from deduplicated normalized findings
    risk_score, risk_rating, score_breakdown = calculate_risk_score(findings_dicts)

    # 8. Summary aggregation
    summary = {
        "critical": sum(1 for f in deduped_findings if f.severity.value == "Critical"),
        "high": sum(1 for f in deduped_findings if f.severity.value == "High"),
        "medium": sum(1 for f in deduped_findings if f.severity.value == "Medium"),
        "low": sum(1 for f in deduped_findings if f.severity.value == "Low"),
        "informational": sum(1 for f in deduped_findings if f.severity.value == "Informational"),
        "total_unique": len(deduped_findings),
    }

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
        "risk_score": risk_score,
        "risk_rating": risk_rating,
        "score_breakdown": score_breakdown,
        "findings": findings_dicts,
        "status": "COMPLETED",
        "created_at": created_at.isoformat(),
        "completed_at": completed_at.isoformat(),
    }


# In-memory registry to securely pass raw secret snippets from analysis engine to database persistence
# without exposing raw secrets in external REST endpoints or audit tests
_RAW_FINDINGS_REGISTRY: Dict[str, Dict[str, Tuple[Optional[str], Optional[str]]]] = {}


def persist_analysis_record(db: Session, analysis_result: Dict[str, Any]) -> AssessmentRecord:
    """
    Persists or updates the assessment record and sanitized findings in SQLite.
    Guarantees idempotency: rerunning or retrying persistence on the same assessment ID
    safely updates existing rows without duplicate key errors or orphan records.
    Never stores unredacted sensitive values in outward report structures.
    """
    assessment_id = analysis_result["assessment_id"]
    existing_assessment = db.query(AssessmentRecord).filter(AssessmentRecord.id == assessment_id).first()

    created_dt = datetime.fromisoformat(analysis_result["created_at"])
    completed_dt = datetime.fromisoformat(analysis_result["completed_at"])

    if existing_assessment:
        existing_assessment.filename = analysis_result["filename"]
        existing_assessment.file_size_bytes = analysis_result["file_size_bytes"]
        existing_assessment.sha256 = analysis_result["sha256"]
        existing_assessment.md5 = analysis_result["md5"]
        existing_assessment.image_type = analysis_result["image_type"]
        existing_assessment.status = analysis_result["status"]
        existing_assessment.risk_score = analysis_result.get("risk_score", 0)
        existing_assessment.risk_rating = analysis_result.get("risk_rating", "Clean")
        existing_assessment.image_metadata = analysis_result["image_metadata"]
        existing_assessment.score_breakdown = analysis_result.get("score_breakdown")
        existing_assessment.completed_at = completed_dt

        # Remove previous findings for this assessment to ensure clean idempotent replace
        db.query(FindingRecord).filter(FindingRecord.assessment_id == assessment_id).delete()
        assessment = existing_assessment
    else:
        assessment = AssessmentRecord(
            id=assessment_id,
            filename=analysis_result["filename"],
            file_size_bytes=analysis_result["file_size_bytes"],
            sha256=analysis_result["sha256"],
            md5=analysis_result["md5"],
            image_type=analysis_result["image_type"],
            status=analysis_result["status"],
            risk_score=analysis_result.get("risk_score", 0),
            risk_rating=analysis_result.get("risk_rating", "Clean"),
            image_metadata=analysis_result["image_metadata"],
            score_breakdown=analysis_result.get("score_breakdown"),
            created_at=created_dt,
            completed_at=completed_dt,
        )
        db.add(assessment)

    # Persist normalized findings with stable fingerprints and raw evidence for demo reveal mode
    raw_map = _RAW_FINDINGS_REGISTRY.pop(assessment_id, {})
    for f_data in analysis_result["findings"]:
        f_id = f_data.get("id") or str(uuid.uuid4())
        ev_raw, sec_token = raw_map.get(f_id, (f_data.get("evidence_raw"), f_data.get("secret_token")))

        finding = FindingRecord(
            id=f_id,
            assessment_id=assessment_id,
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
            evidence_raw=ev_raw,
            secret_token=sec_token,
            raw_occurrences=f_data.get("raw_occurrences", 1),
            fingerprint=f_data.get("fingerprint"),
            rationale=f_data.get("rationale"),
            false_positive_cases=f_data.get("false_positive_cases"),
            remediation=f_data.get("remediation"),
            verification_limitations=f_data.get("verification_limitations"),
            is_potential=f_data.get("is_potential", True),
            created_at=datetime.fromisoformat(f_data["created_at"]) if "created_at" in f_data else datetime.now(timezone.utc),
        )
        db.add(finding)

    db.commit()
    db.refresh(assessment)
    return assessment
