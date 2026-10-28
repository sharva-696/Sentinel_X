import uuid
import hashlib
from enum import Enum
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator

from backend.app.utils.masking import sanitize_evidence


class FindingSeverity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class FindingConfidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


def compute_finding_fingerprint(
    rule_id: str,
    category: str,
    evidence_masked: str,
    byte_offset: Optional[str] = None,
) -> str:
    """
    Computes a deterministic, stable SHA-256 fingerprint for a finding.
    Based on rule identifier, category, and sanitized evidence content.
    Never includes raw secret values in the fingerprint.
    """
    norm_rule = (rule_id or "GENERIC_RULE").strip().upper()
    norm_cat = (category or "General").strip().lower()
    norm_evidence = (evidence_masked or "").strip()
    
    # Normalize whitespace to make fingerprint robust against minor formatting changes
    norm_evidence = " ".join(norm_evidence.split())

    content = f"{norm_rule}|{norm_cat}|{norm_evidence}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class NormalizedFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    assessment_id: str
    rule_id: str
    title: str
    category: str
    severity: FindingSeverity
    confidence: FindingConfidence
    detection_method: str
    byte_offset: Optional[str] = None
    additional_offsets: List[str] = Field(default_factory=list)
    section: Optional[str] = None
    evidence_masked: str
    raw_occurrences: int = 1
    fingerprint: str
    rationale: Optional[str] = None
    false_positive_cases: Optional[str] = None
    remediation: Optional[str] = None
    verification_limitations: Optional[str] = None
    is_potential: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, v: Any) -> FindingSeverity:
        if isinstance(v, FindingSeverity):
            return v
        if isinstance(v, str):
            for item in FindingSeverity:
                if item.value.lower() == v.strip().lower():
                    return item
        return FindingSeverity.LOW

    @field_validator("confidence", mode="before")
    @classmethod
    def validate_confidence(cls, v: Any) -> FindingConfidence:
        if isinstance(v, FindingConfidence):
            return v
        if isinstance(v, str):
            for item in FindingConfidence:
                if item.value.lower() == v.strip().lower():
                    return item
        return FindingConfidence.MEDIUM

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "assessment_id": self.assessment_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "detection_method": self.detection_method,
            "byte_offset": self.byte_offset,
            "additional_offsets": self.additional_offsets,
            "section": self.section,
            "evidence_masked": self.evidence_masked,
            "raw_occurrences": self.raw_occurrences,
            "fingerprint": self.fingerprint,
            "rationale": self.rationale,
            "false_positive_cases": self.false_positive_cases,
            "remediation": self.remediation,
            "verification_limitations": self.verification_limitations,
            "is_potential": self.is_potential,
            "created_at": self.created_at.isoformat(),
        }


def normalize_finding(raw: Dict[str, Any], assessment_id: str) -> NormalizedFinding:
    """
    Transforms a raw finding dictionary into a strictly validated NormalizedFinding.
    Guarantees sanitized evidence and generates a stable deduplication fingerprint.
    """
    rule_id = raw.get("rule_id", "GENERIC_RULE")
    category = raw.get("category", "General Security")
    title = raw.get("title", f"Security Indicator {rule_id}")
    detection_method = raw.get("detection_method", "Static Analysis")
    raw_evidence = raw.get("evidence_masked") or raw.get("evidence") or ""

    # Enforce multi-pass sanitization
    sanitized_evidence = sanitize_evidence(str(raw_evidence))

    primary_offset = raw.get("byte_offset")
    fingerprint = raw.get("fingerprint") or compute_finding_fingerprint(
        rule_id, category, sanitized_evidence, primary_offset
    )

    additional_offsets = raw.get("additional_offsets") or []
    occurrences = int(raw.get("raw_occurrences", 1))

    return NormalizedFinding(
        id=raw.get("id") or str(uuid.uuid4()),
        assessment_id=assessment_id,
        rule_id=rule_id,
        title=title,
        category=category,
        severity=raw.get("severity", "Low"),
        confidence=raw.get("confidence", "Medium"),
        detection_method=detection_method,
        byte_offset=primary_offset,
        additional_offsets=list(additional_offsets),
        section=raw.get("section"),
        evidence_masked=sanitized_evidence,
        raw_occurrences=occurrences,
        fingerprint=fingerprint,
        rationale=raw.get("rationale"),
        false_positive_cases=raw.get("false_positive_cases"),
        remediation=raw.get("remediation"),
        verification_limitations=raw.get("verification_limitations"),
        is_potential=raw.get("is_potential", True),
    )


def deduplicate_findings(findings: List[NormalizedFinding]) -> List[NormalizedFinding]:
    """
    Deduplicates a collection of normalized findings based on stable fingerprints.
    Merges occurrences, compiles all observed byte offsets, and retains primary location.
    Preserves distinct findings with different rules or distinct evidence.
    """
    dedup_map: Dict[str, NormalizedFinding] = {}

    for f in findings:
        fp = f.fingerprint
        if fp not in dedup_map:
            # Create a copy with fresh list for additional offsets
            dedup_map[fp] = NormalizedFinding(
                id=f.id,
                assessment_id=f.assessment_id,
                rule_id=f.rule_id,
                title=f.title,
                category=f.category,
                severity=f.severity,
                confidence=f.confidence,
                detection_method=f.detection_method,
                byte_offset=f.byte_offset,
                additional_offsets=list(f.additional_offsets),
                section=f.section,
                evidence_masked=f.evidence_masked,
                raw_occurrences=f.raw_occurrences,
                fingerprint=f.fingerprint,
                rationale=f.rationale,
                false_positive_cases=f.false_positive_cases,
                remediation=f.remediation,
                verification_limitations=f.verification_limitations,
                is_potential=f.is_potential,
                created_at=f.created_at,
            )
        else:
            existing = dedup_map[fp]
            existing.raw_occurrences += f.raw_occurrences

            # Collect offsets
            if f.byte_offset and f.byte_offset != existing.byte_offset:
                if f.byte_offset not in existing.additional_offsets:
                    existing.additional_offsets.append(f.byte_offset)

            for extra in f.additional_offsets:
                if extra and extra != existing.byte_offset and extra not in existing.additional_offsets:
                    existing.additional_offsets.append(extra)

    return list(dedup_map.values())
