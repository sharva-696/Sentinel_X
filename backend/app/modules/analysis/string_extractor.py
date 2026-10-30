import re
from typing import Dict, Any, List, Tuple
from backend.app.utils.masking import sanitize_evidence

# Printable ASCII characters (0x20 space through 0x7E tilde, plus tab \t)
PRINTABLE_ASCII_REGEX = re.compile(rb"[\x20-\x7E\t]{%d,}" % 4)

# Common indicators for categorizing interesting strings
INDICATOR_PATTERNS = {
    "url": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    "ipv4": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
    "wifi": re.compile(r"(?i)\b(ssid|wpa2|wpa|psk|wifi_config|sta_config|softap)\b"),
    "debug_log": re.compile(r"(?i)\b(esp_log[ewidv]|guru meditation|assert failed|backtrace:)\b"),
    "certificate": re.compile(r"-----BEGIN [A-Z ]+-----"),
    "mqtt": re.compile(r"(?i)\b(mqtt://|mqtts://|tcp://[^\s]+:1883|tcp://[^\s]+:8883)\b"),
    "esp_idf_version": re.compile(r"\bESP-IDF\s+v[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-zA-Z0-9_\-\.]+)?\b"),
}


def extract_strings_with_offsets(
    data: bytes, min_length: int = 4, max_strings: int = 25000
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Extracts printable ASCII strings and their exact byte offsets from raw binary data.
    Enforces a strict upper bound to prevent resource exhaustion and JSON bloating.
    
    Returns:
        (strings_list, metadata)
    """
    pattern = re.compile(rb"[\x20-\x7E\t]{%d,}" % min_length)
    extracted: List[Dict[str, Any]] = []
    total_found = 0
    is_truncated = False

    for match in pattern.finditer(data):
        total_found += 1
        if len(extracted) < max_strings:
            raw_bytes = match.group(0)
            offset = match.start()
            try:
                decoded = raw_bytes.decode("ascii", errors="replace").strip()
            except Exception:
                decoded = raw_bytes.decode("utf-8", errors="replace").strip()

            if len(decoded) >= min_length:
                extracted.append({
                    "offset": f"0x{offset:06x}",
                    "offset_dec": offset,
                    "length": len(decoded),
                    "value": decoded,
                })
        else:
            is_truncated = True

    metadata = {
        "min_length": min_length,
        "max_strings_limit": max_strings,
        "extracted_count": len(extracted),
        "total_detected_count": total_found,
        "is_truncated": is_truncated,
    }

    return extracted, metadata


def categorize_strings(extracted_strings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Scans extracted strings and tags them by investigative category.
    All exposed string values are sanitized to prevent accidental leakage of raw credentials.
    """
    categorized: Dict[str, List[Dict[str, Any]]] = {
        "urls": [],
        "ip_addresses": [],
        "wifi_indicators": [],
        "debug_logs": [],
        "certificates": [],
        "mqtt_endpoints": [],
        "sdk_versions": [],
    }

    for item in extracted_strings:
        val = item["value"]
        offset = item["offset"]
        # Redact any embedded passwords, keys, or credentials before adding to categorized views
        sanitized_val = sanitize_evidence(val)

        if INDICATOR_PATTERNS["url"].search(val):
            categorized["urls"].append({"offset": offset, "value": sanitized_val})

        if INDICATOR_PATTERNS["ipv4"].search(val):
            categorized["ip_addresses"].append({"offset": offset, "value": sanitized_val})

        if INDICATOR_PATTERNS["wifi"].search(val):
            categorized["wifi_indicators"].append({"offset": offset, "value": sanitized_val})

        if INDICATOR_PATTERNS["debug_log"].search(val):
            categorized["debug_logs"].append({"offset": offset, "value": sanitized_val})

        if INDICATOR_PATTERNS["certificate"].search(val):
            categorized["certificates"].append({"offset": offset, "value": sanitized_val})

        if INDICATOR_PATTERNS["mqtt"].search(val):
            categorized["mqtt_endpoints"].append({"offset": offset, "value": sanitized_val})

        if INDICATOR_PATTERNS["esp_idf_version"].search(val):
            categorized["sdk_versions"].append({"offset": offset, "value": sanitized_val})

    return categorized
