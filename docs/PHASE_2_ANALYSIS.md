# Sentinel-X: Phase 2 Offline Firmware Analysis Engine

## Overview

The Sentinel-X Phase 2 analysis engine provides automated, offline, and evidence-backed security assessment of ESP32 firmware binaries. The engine runs completely without physical hardware, internet access, or live device interaction.

---

## 1. Analysis Pipeline Architecture

```mermaid
flowchart TD
    Binary[Uploaded Binary Payload] --> Val[Input Validator]
    Val -->|Max 32MB, Reject Empty| Hash[Cryptographic Hasher (SHA-256 & MD5)]
    Hash --> Sniff[Format Classifier]
    
    Sniff -->|0xE9 + Flash Segments| AppParser[ESP32 App Binary Parser]
    Sniff -->|0xE9 + IRAM-only <64KB| BootParser[Bootloader Binary Parser]
    Sniff -->|0xAA50 & <=0x1000| PartParser[Partition Table Parser]
    Sniff -->|0xAA50 at 0x8000/0x9000| FlashDumpParser[Full Flash Dump Parser]
    Sniff -->|Non-matching / Corrupt| RawParser[Generic String Parser]

    AppParser --> StrExt[Printable String Extractor (>= 4 chars, with Offsets)]
    BootParser --> StrExt
    PartParser --> StrExt
    FlashDumpParser --> StrExt
    RawParser --> StrExt

    StrExt --> SecScan[Evidence-Based Secret Scanner]
    SecScan --> Sanitize[Multi-Pass Secret Redaction Engine]
    Sanitize --> Result[Structured Assessment & Findings Result]
    Result --> DB[(SQLite Persistence)]
```

### Pipeline Components

1. **Input Validator (`backend/app/modules/analysis/validator.py`)**:
   - Enforces 32 MB maximum size constraint.
   - Rejects empty (0-byte) inputs with HTTP 400.
   - Saves files to secure storage paths using UUID-based names to prevent directory traversal or file execution.
2. **Cryptographic Hasher (`backend/app/utils/crypto.py`)**:
   - Streams chunked SHA-256 and MD5 hashes directly from byte streams.
3. **ESP Binary Parser (`backend/app/modules/analysis/esp_parser.py`)**:
   - Recognizes ESP32 image formats: `APP_BINARY`, `BOOTLOADER_BINARY`, `PARTITION_TABLE`, `FULL_FLASH_DUMP`, and `RAW_BINARY`.
   - Extracts ESP image headers (magic `0xE9`, segment counts, entry points, flash mode/frequency/size, chip target, appended hash flag).
   - Classifies memory regions (`DROM`, `IROM`, `IRAM`, `DRAM`).
   - Reports partial or malformed headers gracefully without crashing.
4. **String Extractor (`backend/app/modules/analysis/string_extractor.py`)**:
   - Extracts printable ASCII strings ($\ge 4$ characters) indexed by exact byte offset.
   - Caps extracted results (default 5,000 strings) to prevent JSON bloating and resource exhaustion.
   - Categorizes investigative strings (URLs, IPs, Wi-Fi strings, debug banners, certificates, MQTT endpoints, SDK versions).
5. **Secret Scanner & Auditor (`backend/app/modules/analysis/secret_scanner.py`, `secret_rules.py`)**:
   - Matches evidence-backed patterns: Wi-Fi credentials, PEM private keys, AWS access keys, GitHub tokens, Bearer tokens, plaintext MQTT credentials, cleartext HTTP endpoints, and verbose debug banners.
   - Calculates Shannon entropy for random token heuristics.
   - Groups duplicate matches of the same secret into single findings with multiple offset references.
6. **Masking & Redaction (`backend/app/utils/masking.py`)**:
   - Multi-pass sanitization redacts private keys (`[REDACTED PRIVATE KEY MATERIAL]`), Wi-Fi passphrases, API keys (`AKIA**************LE`), and URL passwords before persistence or output.
7. **Persistence Engine (`backend/app/modules/analysis/engine.py`)**:
   - Saves assessment records and sanitized findings to SQLite using SQLAlchemy ORM.

---

## 2. Supported Input Types & Behavior

| Profile | Identification Criteria | Analysis Behavior |
|---|---|---|
| **Application Firmware (`APP_BINARY`)** | Magic `0xE9`, flash-mapped segment in DROM (`0x3F40xxxx`) or IROM (`0x400Dxxxx` / `0x42xxxxxx`) | Full header inspection, segment memory mapping, string extraction, secret scanning, SDK version identification. |
| **Bootloader (`BOOTLOADER_BINARY`)** | Magic `0xE9`, size $< 64$ KB, all segments in IRAM/DRAM, entry point in IRAM | Bootloader header validation, debug banner extraction, secret scanning. |
| **Partition Table (`PARTITION_TABLE`)** | Magic `0xAA50`, size $\le 4$ KB | Parses partition entries (`factory`, `ota_0`, `ota_1`, `nvs`, `spiffs`), verifies OTA redundancy. |
| **Full Flash Dump (`FULL_FLASH_DUMP`)** | Size $\ge 1$ MB, partition table magic `0xAA50` at offset `0x8000` or `0x9000` | Carves partition table, locates partitions, and analyzes application binaries. |
| **Raw / Unrecognized (`RAW_BINARY`)** | Non-ESP headers or corrupted magic | Falls back to string extraction, Shannon entropy profiling, and secret pattern matching without crashing. |

---

## 3. How to Run Tests

From the repository root:

```bash
cd /home/sharva/Sentinel_X/backend
python3 -m pytest
```

All 27 automated unit and integration tests run in under 0.2 seconds without physical hardware.

---

## 4. API Usage: Offline Firmware Analysis

### Endpoint: `POST /api/firmware/analyze`

Accepts a multipart file upload (`file: binary data`).

#### Example Request using curl:
```bash
curl -X POST "http://localhost:8000/api/firmware/analyze" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@esp32_sample_firmware.bin;type=application/octet-stream"
```

#### Real Sanitized JSON Response (Generated from Synthetic 327-byte Test Binary):

```json
{
  "assessment_id": "6a5545e1-42cb-4f77-862c-3f7fbd4d3a03",
  "filename": "esp32_sample_firmware.bin",
  "file_size_bytes": 327,
  "sha256": "b1010e955a86037fa30c2187670fa8b2e4e5945937c7fee2b61fe24908336f2d",
  "md5": "303f807f18da1abd93f5049b707a80cb",
  "image_type": "APP_BINARY",
  "parser_status": "SUCCESS",
  "parser_warnings": [],
  "image_metadata": {
    "image_type": "APP_BINARY",
    "parser_status": "SUCCESS",
    "header_valid": true,
    "header_magic": "0xe9",
    "chip_target": "ESP32",
    "segments_count": 2,
    "spi_mode": "DIO",
    "spi_speed": "40MHz",
    "spi_size": "4MB",
    "entry_point": "0x40080644",
    "hash_appended": true,
    "segments": [
      {
        "segment_index": 0,
        "load_address": "0x3f400000",
        "data_length": 223,
        "section": "DROM",
        "file_offset": "0x000020"
      },
      {
        "segment_index": 1,
        "load_address": "0x40080000",
        "data_length": 64,
        "section": "IRAM",
        "file_offset": "0x000107"
      }
    ],
    "partitions": [],
    "warnings": []
  },
  "strings_summary": {
    "min_length": 4,
    "max_strings_limit": 5000,
    "extracted_count": 6,
    "total_detected_count": 6,
    "is_truncated": false
  },
  "categorized_strings": {
    "urls": [
      {
        "offset": "0x00006d",
        "value": "http://api.insecure-iot-endpoint.com/telemetry"
      }
    ],
    "ip_addresses": [],
    "wifi_indicators": [],
    "debug_logs": [
      {
        "offset": "0x0000d8",
        "value": "ESP_LOGI(TAG, 'System boot complete');"
      }
    ],
    "certificates": [],
    "mqtt_endpoints": [
      {
        "offset": "0x00009c",
        "value": "mqtt://device_user:******@broker.iot.net:1883"
      }
    ],
    "sdk_versions": [
      {
        "offset": "0x000020",
        "value": "ESP-IDF v4.4.3"
      }
    ]
  },
  "findings_summary": {
    "critical": 0,
    "high": 2,
    "medium": 1,
    "low": 1,
    "informational": 0,
    "total_unique": 4
  },
  "risk_rating": "High",
  "findings": [
    {
      "id": "f891ad57-c0f8-4f46-8386-89ed4698f27c",
      "assessment_id": "6a5545e1-42cb-4f77-862c-3f7fbd4d3a03",
      "rule_id": "SEC-WIFI-001",
      "title": "Potential Hardcoded Wi-Fi Credentials",
      "category": "Network Credentials",
      "severity": "High",
      "confidence": "Medium",
      "detection_method": "Wi-Fi Configuration Pattern Matching",
      "byte_offset": "0x00002f",
      "additional_offsets": [],
      "section": null,
      "evidence_masked": "wifi_password = '**********************'",
      "raw_occurrences": 1,
      "rationale": "Plaintext Wi-Fi credentials in application binaries expose the local network to unauthorized access if firmware is extracted.",
      "false_positive_cases": "SDK template strings ('your_password', 'my_wifi_pass') or test suite binaries.",
      "remediation": "Remove hardcoded credentials from source code. Implement dynamic runtime provisioning using ESP-IDF WiFi Provisioning (BLE/SoftAP) and store credentials in encrypted NVS.",
      "verification_limitations": "Static match; does not verify if the credentials match any real access point.",
      "is_potential": true
    },
    {
      "id": "4621c7ec-ccad-4705-ad4c-53cb26f22b5f",
      "assessment_id": "6a5545e1-42cb-4f77-862c-3f7fbd4d3a03",
      "rule_id": "SEC-CLOUD-001",
      "title": "AWS Access Key Identifier",
      "category": "Cloud Credentials",
      "severity": "High",
      "confidence": "High",
      "detection_method": "Regex Key Pattern",
      "byte_offset": "0x000058",
      "additional_offsets": [],
      "section": null,
      "evidence_masked": "AKIA**************23",
      "raw_occurrences": 1,
      "rationale": "AWS Access Key IDs embedded in IoT devices can expose cloud storage (S3), IoT Core, or administrative IAM permissions.",
      "false_positive_cases": "Deprecated, invalid, or documentation example keys (e.g. AKIAIOSFODNN7EXAMPLE).",
      "remediation": "Revoke the hardcoded access key immediately in AWS IAM. Use short-lived AWS STS credentials or connect to IoT Core using X.509 device certificates.",
      "verification_limitations": "Static syntax match only. Does not query AWS STS or IAM to verify if the key is active or revoked.",
      "is_potential": true
    },
    {
      "id": "2d98fae8-439a-4780-ba00-9fcc777fbbae",
      "assessment_id": "6a5545e1-42cb-4f77-862c-3f7fbd4d3a03",
      "rule_id": "SEC-NET-001",
      "title": "Insecure Plaintext HTTP Endpoint",
      "category": "Insecure Protocols",
      "severity": "Low",
      "confidence": "Medium",
      "detection_method": "URL Pattern Matching",
      "byte_offset": "0x00006d",
      "additional_offsets": [],
      "section": null,
      "evidence_masked": "http://api.insecure-iot-endpoint.com/telemetry",
      "raw_occurrences": 1,
      "rationale": "Cleartext HTTP endpoints are vulnerable to man-in-the-middle inspection and tampering.",
      "false_positive_cases": "Captive portal redirect URLs, XML namespace URIs, documentation URLs.",
      "remediation": "Migrate API communications to HTTPS (TLS 1.2 or 1.3) and enforce certificate validation in ESP-IDF.",
      "verification_limitations": "Static detection; does not prove the URL is active or used for sensitive data transfer.",
      "is_potential": true
    },
    {
      "id": "b68b0d68-9d9a-44e4-af8e-e7c930d8b1b7",
      "assessment_id": "6a5545e1-42cb-4f77-862c-3f7fbd4d3a03",
      "rule_id": "SEC-NET-002",
      "title": "Plaintext MQTT Broker Credentials",
      "category": "Insecure Protocols",
      "severity": "Medium",
      "confidence": "Medium",
      "detection_method": "MQTT URI Pattern Matching",
      "byte_offset": "0x00009c",
      "additional_offsets": [],
      "section": null,
      "evidence_masked": "mqtt://device_user:******@broker.iot.net:1883",
      "raw_occurrences": 1,
      "rationale": "Unencrypted MQTT communication with embedded credentials exposes telemetric data and device control commands to eavesdropping and tampering.",
      "false_positive_cases": "Local loopback test endpoints (e.g. mqtt://user:pass@127.0.0.1).",
      "remediation": "Switch to secure MQTT over TLS (`mqtts://`, port 8883) and authenticate using X.509 client certificates or secure tokens.",
      "verification_limitations": "Does not verify broker connectivity or network firewalling.",
      "is_potential": true
    }
  ],
  "status": "COMPLETED",
  "created_at": "2026-10-28T18:06:40.707045+00:00",
  "completed_at": "2026-10-28T18:06:40.707695+00:00"
}
```

---

## 5. Security & Verification Limitations

1. **Static Match Disclaimers**: Detected API keys, Wi-Fi PSKs, and Bearer tokens are heuristic matches. The tool does not verify whether credentials are live or active on external services.
2. **Plaintext HTTP**: A detected `http://` string indicates cleartext transmission risk, but may represent an XML namespace, documentation URI, or captive portal redirect rather than an active data leak.
3. **Flash Settings vs. Hardware**: Image header settings (e.g. flash mode DIO, 40MHz, 4MB) reflect compiler build settings, not verified physical silicon limits.
4. **No Destructive Operations**: Firmware files are inspected as inert data; code is never executed, and uploaded files are stored using random UUIDs and removed upon cleanup.
