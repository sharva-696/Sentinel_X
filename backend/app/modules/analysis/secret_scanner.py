import math
import uuid
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from backend.app.modules.analysis.secret_rules import DETECTION_RULES
from backend.app.utils.masking import sanitize_evidence, mask_secret


def calculate_shannon_entropy(data_str: str) -> float:
    """
    Calculates the Shannon entropy of a string.
    Higher entropy indicates random/cryptographic token material.
    """
    if not data_str:
        return 0.0
    entropy = 0.0
    length = len(data_str)
    counts: Dict[str, int] = {}
    for c in data_str:
        counts[c] = counts.get(c, 0) + 1

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def scan_for_secrets(
    extracted_strings: List[Dict[str, Any]],
    raw_data: bytes,
    assessment_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Scans extracted strings and raw binary data using evidence-based detection rules.
    Performs occurrence deduplication and ensures evidence is redacted before return.
    """
    if assessment_id is None:
        assessment_id = str(uuid.uuid4())

    # Raw matches dictionary keyed by (rule_id, sanitized_match, identity_hash) to deduplicate genuine equivalents
    dedup_map: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    # 1. Scan extracted printable strings
    for item in extracted_strings:
        val = item["value"]
        offset = item["offset"]

        for rule in DETECTION_RULES:
            match = rule["pattern"].search(val)
            if not match:
                continue

            matched_text = match.group(0)

            # Check minimum entropy if required by rule
            if rule["min_entropy"] > 0:
                ent = calculate_shannon_entropy(matched_text)
                if ent < rule["min_entropy"]:
                    continue

            # Identify the underlying secret token to distinguish distinct credentials
            # without exposing raw secrets in the fingerprint or finding dictionary
            secret_token = match.group(1) if match.groups() else matched_text
            identity_hash = hashlib.sha256(secret_token.strip().encode("utf-8", errors="replace")).hexdigest()[:16]

            sanitized_snippet = sanitize_evidence(val)
            key = (rule["rule_id"], sanitized_snippet, identity_hash)

            if key not in dedup_map:
                dedup_map[key] = {
                    "id": str(uuid.uuid4()),
                    "assessment_id": assessment_id,
                    "rule_id": rule["rule_id"],
                    "title": rule["title"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "confidence": rule["confidence"],
                    "detection_method": rule["detection_method"],
                    "byte_offset": offset,
                    "additional_offsets": [],
                    "section": None,
                    "evidence_masked": sanitized_snippet,
                    "raw_occurrences": 1,
                    "identity_hash": identity_hash,
                    "rationale": rule["rationale"],
                    "false_positive_cases": rule["false_positive_cases"],
                    "remediation": rule["remediation"],
                    "verification_limitations": rule["verification_limitations"],
                    "is_potential": rule["is_potential"],
                }
            else:
                existing = dedup_map[key]
                existing["raw_occurrences"] += 1
                if offset not in existing["additional_offsets"] and offset != existing["byte_offset"]:
                    existing["additional_offsets"].append(offset)

    # 2. Check for multi-line PEM Private Keys in raw binary
    # PEM certificates span across multiple lines and null bytes
    pem_rule = next((r for r in DETECTION_RULES if r["rule_id"] == "SEC-KEY-001"), None)
    if pem_rule:
        import re
        pem_raw_matches = re.finditer(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----", raw_data)
        for p_match in pem_raw_matches:
            p_offset = f"0x{p_match.start():06x}"
            # Extract header snippet safely
            snippet = raw_data[p_match.start() : min(len(raw_data), p_match.start() + 120)].decode(
                "ascii", errors="replace"
            )
            sanitized_snippet = sanitize_evidence(snippet)
            p_identity = hashlib.sha256(p_match.group(0)).hexdigest()[:16]
            key = (pem_rule["rule_id"], sanitized_snippet, p_identity)

            if key not in dedup_map:
                dedup_map[key] = {
                    "id": str(uuid.uuid4()),
                    "assessment_id": assessment_id,
                    "rule_id": pem_rule["rule_id"],
                    "title": pem_rule["title"],
                    "category": pem_rule["category"],
                    "severity": pem_rule["severity"],
                    "confidence": pem_rule["confidence"],
                    "detection_method": pem_rule["detection_method"],
                    "byte_offset": p_offset,
                    "additional_offsets": [],
                    "section": None,
                    "evidence_masked": sanitized_snippet,
                    "raw_occurrences": 1,
                    "identity_hash": p_identity,
                    "rationale": pem_rule["rationale"],
                    "false_positive_cases": pem_rule["false_positive_cases"],
                    "remediation": pem_rule["remediation"],
                    "verification_limitations": pem_rule["verification_limitations"],
                    "is_potential": pem_rule["is_potential"],
                }
            else:
                existing = dedup_map[key]
                existing["raw_occurrences"] += 1
                if p_offset not in existing["additional_offsets"] and p_offset != existing["byte_offset"]:
                    existing["additional_offsets"].append(p_offset)

    return list(dedup_map.values())
