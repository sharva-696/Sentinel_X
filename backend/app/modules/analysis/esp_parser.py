import struct
from typing import Dict, Any, List, Optional, Tuple

ESP_IMAGE_MAGIC = 0xE9
PARTITION_TABLE_MAGIC = 0xAA50
PARTITION_TABLE_MD5_MAGIC = 0xEBEB

# Flash Mode mappings from ESP-IDF
FLASH_MODES = {
    0x00: "QIO",
    0x01: "QOUT",
    0x02: "DIO",
    0x03: "DOUT",
    0x04: "FAST_READ",
    0x05: "SLOW_READ",
}

# Flash Frequency mappings
FLASH_FREQUENCIES = {
    0x00: "40MHz",
    0x01: "26MHz",
    0x02: "20MHz",
    0x0F: "80MHz",
}

# Flash Sizes encoded in header
FLASH_SIZES = {
    0x00: "1MB",
    0x01: "2MB",
    0x02: "4MB",
    0x03: "8MB",
    0x04: "16MB",
    0x05: "32MB",
}

# ESP32 Chip IDs from image header
CHIP_TARGETS = {
    0x0000: "ESP32",
    0x0002: "ESP32-S2",
    0x0005: "ESP32-C3",
    0x0009: "ESP32-S3",
    0x000C: "ESP32-C2",
    0x000D: "ESP32-C6",
    0x0010: "ESP32-H2",
    0x0012: "ESP32-P4",
}

PARTITION_TYPES = {
    0x00: "app",
    0x01: "data",
}

PARTITION_SUBTYPES = {
    # App subtypes
    (0x00, 0x00): "factory",
    (0x00, 0x10): "ota_0",
    (0x00, 0x11): "ota_1",
    (0x00, 0x20): "test",
    # Data subtypes
    (0x01, 0x00): "ota",
    (0x01, 0x01): "phy",
    (0x01, 0x02): "nvs",
    (0x01, 0x03): "coredump",
    (0x01, 0x04): "nvs_keys",
    (0x01, 0x81): "fat",
    (0x01, 0x82): "spiffs",
}


def classify_memory_section(load_addr: int) -> str:
    """Classifies ESP32 load address into standard memory region."""
    if 0x3FF00000 <= load_addr < 0x40000000:
        return "DRAM"
    elif 0x3F400000 <= load_addr < 0x3F800000:
        return "DROM"
    elif 0x40000000 <= load_addr < 0x40070000:
        return "IRAM_ROM"
    elif 0x40070000 <= load_addr < 0x400A0000:
        return "IRAM"
    elif 0x400D0000 <= load_addr < 0x40400000:
        return "IROM"
    elif 0x42000000 <= load_addr < 0x44000000:
        return "IROM/DROM (Ext Flash)"
    return "UNKNOWN_SECTION"


def parse_partition_table_bytes(data: bytes, offset_in_file: int = 0) -> List[Dict[str, Any]]:
    """
    Parses a sequence of 32-byte partition table entries.
    """
    partitions = []
    entry_size = 32
    max_entries = 95  # 0xC00 / 32 = 96 (last entry is often MD5 checksum)

    for i in range(max_entries):
        entry_offset = offset_in_file + (i * entry_size)
        if entry_offset + entry_size > len(data):
            break

        chunk = data[entry_offset : entry_offset + entry_size]
        magic = struct.unpack("<H", chunk[0:2])[0]

        if magic == PARTITION_TABLE_MD5_MAGIC:
            # MD5 checksum entry
            break
        if magic != PARTITION_TABLE_MAGIC:
            # Reached end of partition table or uninitialized space
            break

        part_type = chunk[2]
        part_subtype = chunk[3]
        part_offset = struct.unpack("<I", chunk[4:8])[0]
        part_size = struct.unpack("<I", chunk[8:12])[0]
        raw_label = chunk[12:28]
        label = raw_label.split(b"\x00")[0].decode("ascii", errors="replace")
        flags = struct.unpack("<I", chunk[28:32])[0]

        type_str = PARTITION_TYPES.get(part_type, f"0x{part_type:02x}")
        subtype_str = PARTITION_SUBTYPES.get((part_type, part_subtype), f"0x{part_subtype:02x}")

        partitions.append({
            "index": i,
            "label": label,
            "type": type_str,
            "subtype": subtype_str,
            "offset": f"0x{part_offset:08x}",
            "offset_dec": part_offset,
            "size": f"0x{part_size:08x}",
            "size_dec": part_size,
            "encrypted": bool(flags & 0x01),
        })

    return partitions


def detect_image_type(data: bytes) -> str:
    """
    Identifies the profile of the uploaded firmware binary.
    """
    size = len(data)

    # 1. Check for Partition Table (typical size <= 0x1000 and magic 0xAA50 at offset 0)
    if size <= 0x1000 and len(data) >= 32:
        if struct.unpack("<H", data[0:2])[0] == PARTITION_TABLE_MAGIC:
            return "PARTITION_TABLE"

    # 2. Check for Full Flash Dump
    # Standard sizes: 2MB, 4MB, 8MB, 16MB, 32MB
    # Look for partition table at offset 0x8000 or 0x9000
    if size >= 1024 * 1024:
        for pt_offset in [0x8000, 0x9000]:
            if size > pt_offset + 32:
                if struct.unpack("<H", data[pt_offset : pt_offset + 2])[0] == PARTITION_TABLE_MAGIC:
                    return "FULL_FLASH_DUMP"

    # 3. Check for ESP Image Magic at offset 0
    if size >= 24 and data[0] == ESP_IMAGE_MAGIC:
        seg_count = data[1]
        has_flash_mapped_segment = False

        # Scan available segment headers to see if any segment is mapped to DROM or IROM
        seg_offset = 24
        for _ in range(min(seg_count, 16)):
            if seg_offset + 8 <= size:
                load_addr, seg_len = struct.unpack("<II", data[seg_offset : seg_offset + 8])
                # Check if mapped to flash DROM or IROM
                if (0x3F400000 <= load_addr < 0x3F800000) or (0x400D0000 <= load_addr < 0x44000000):
                    has_flash_mapped_segment = True
                    break
                seg_offset += 8 + seg_len
            else:
                break

        if has_flash_mapped_segment:
            return "APP_BINARY"

        entry_point = struct.unpack("<I", data[4:8])[0]
        # Bootloader has only IRAM/DRAM segments, small size (< 64KB), and IRAM entry point
        if size <= 65536 and (0x40070000 <= entry_point < 0x40090000 or 0x3F400000 <= entry_point < 0x3F500000):
            return "BOOTLOADER_BINARY"

        return "APP_BINARY"

    return "RAW_BINARY"


def parse_esp_binary(data: bytes) -> Dict[str, Any]:
    """
    Parses binary metadata without throwing unhandled exceptions.
    Returns structured dictionary with metadata, segments, warnings, and parser status.
    """
    file_size = len(data)
    detected_type = detect_image_type(data)

    result: Dict[str, Any] = {
        "image_type": detected_type,
        "parser_status": "NOT_APPLICABLE",
        "header_valid": False,
        "header_magic": None,
        "chip_target": "Unknown / Not Encoded",
        "segments_count": 0,
        "spi_mode": "Unavailable",
        "spi_speed": "Unavailable",
        "spi_size": "Unavailable",
        "entry_point": None,
        "hash_appended": False,
        "segments": [],
        "partitions": [],
        "warnings": [],
    }

    if file_size < 24:
        result["parser_status"] = "INSUFFICIENT_DATA"
        result["warnings"].append(f"Binary length ({file_size} bytes) is too short to contain a valid ESP32 header (min 24 bytes).")
        return result

    # Handle Partition Table binary directly
    if detected_type == "PARTITION_TABLE":
        partitions = parse_partition_table_bytes(data, 0)
        result["parser_status"] = "SUCCESS" if partitions else "FAILED"
        result["partitions"] = partitions
        if not partitions:
            result["warnings"].append("Partition table magic was present but no valid partition entries could be parsed.")
        return result

    # Handle Full Flash Dump partition table discovery
    if detected_type == "FULL_FLASH_DUMP":
        for pt_offset in [0x8000, 0x9000]:
            if file_size > pt_offset + 32:
                parts = parse_partition_table_bytes(data, pt_offset)
                if parts:
                    result["partitions"] = parts
                    result["warnings"].append(f"Detected full flash dump layout with partition table at offset 0x{pt_offset:04x}.")
                    break

    # Parse ESP Image Header
    header_magic = data[0]
    result["header_magic"] = f"0x{header_magic:02x}"

    if header_magic != ESP_IMAGE_MAGIC:
        result["parser_status"] = "UNRECOGNIZED"
        result["warnings"].append(
            f"Header magic byte 0x{header_magic:02x} does not match ESP32 image magic (0x{ESP_IMAGE_MAGIC:02x}). "
            "ESP32 structural headers unavailable; string extraction and secret scanning will proceed."
        )
        return result

    result["header_valid"] = True
    segment_count = data[1]
    result["segments_count"] = segment_count

    spi_mode_byte = data[2]
    result["spi_mode"] = FLASH_MODES.get(spi_mode_byte, f"Unknown (0x{spi_mode_byte:02x})")

    spi_size_freq_byte = data[3]
    freq_id = spi_size_freq_byte & 0x0F
    size_id = (spi_size_freq_byte >> 4) & 0x0F
    result["spi_speed"] = FLASH_FREQUENCIES.get(freq_id, f"Unknown (0x{freq_id:02x})")
    result["spi_size"] = FLASH_SIZES.get(size_id, f"Unknown (0x{size_id:02x})")

    entry_point = struct.unpack("<I", data[4:8])[0]
    result["entry_point"] = f"0x{entry_point:08x}"

    # Check extended header (v2 format, e.g. ESP32-S2/S3/C3/C6)
    if file_size >= 24:
        # Check byte 12 (chip_id)
        chip_id = struct.unpack("<H", data[12:14])[0]
        if chip_id in CHIP_TARGETS:
            result["chip_target"] = CHIP_TARGETS[chip_id]
        elif entry_point < 0x40080000 or (0x40080000 <= entry_point < 0x40400000):
            result["chip_target"] = "ESP32"

        # Check hash appended flag (offset 23)
        if data[23] == 0x01:
            result["hash_appended"] = True

    # Parse Segments
    offset = 24
    segments = []
    truncated = False

    for s_idx in range(segment_count):
        if offset + 8 > file_size:
            result["warnings"].append(f"File truncated before segment {s_idx + 1} header at offset 0x{offset:06x}.")
            truncated = True
            break

        load_addr, data_len = struct.unpack("<II", data[offset : offset + 8])
        offset += 8

        if offset + data_len > file_size:
            actual_available = file_size - offset
            result["warnings"].append(
                f"Segment {s_idx + 1} is truncated: expected {data_len} bytes, but only {actual_available} bytes remain."
            )
            data_len = max(0, actual_available)
            truncated = True

        section_name = classify_memory_section(load_addr)
        segments.append({
            "segment_index": s_idx,
            "load_address": f"0x{load_addr:08x}",
            "data_length": data_len,
            "section": section_name,
            "file_offset": f"0x{offset:06x}",
        })
        offset += data_len

        if truncated:
            break

    result["segments"] = segments
    result["parser_status"] = "PARTIAL" if truncated else "SUCCESS"

    return result
