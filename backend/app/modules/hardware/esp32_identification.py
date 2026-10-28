import re
import sys
import subprocess
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

import esptool
from backend.app.config import settings
from backend.app.models.device import DeviceRecord


class IdentificationStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    TIMEOUT = "TIMEOUT"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    PORT_BUSY = "PORT_BUSY"
    UNRECOGNIZED_DEVICE = "UNRECOGNIZED_DEVICE"
    FAILED = "FAILED"


class IdentificationResult(BaseModel):
    status: IdentificationStatus
    port: str
    chip_family: Optional[str] = None
    chip_revision: Optional[int] = None
    mac_address: Optional[str] = None
    crystal_freq: Optional[str] = None
    features: List[str] = Field(default_factory=list)
    flash_size: Optional[str] = None
    flash_vendor_id: Optional[str] = None
    flash_mode: Optional[str] = None
    flash_speed: Optional[str] = None
    sdk_version: Optional[str] = None
    tool_version: str = f"esptool {esptool.__version__}"
    warnings: List[str] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)
    raw_output: Optional[str] = None


MOCK_PROFILES = {
    "esp32": {
        "chip_family": "ESP32 (Revision 3)",
        "chip_revision": 3,
        "mac_address": "24:6f:28:b0:12:34",
        "crystal_freq": "40MHz",
        "features": ["Wi-Fi", "BT", "Dual Core", "240MHz"],
        "flash_size": "4MB",
        "flash_vendor_id": "0x20 (XMC)",
        "flash_mode": "DIO",
        "flash_speed": "40MHz",
        "sdk_version": "UNAVAILABLE_VIA_BOOTLOADER",
        "notes": [
            "Retrieved via non-destructive esptool flash-id query.",
            "SDK version requires firmware image analysis or UART boot log capture.",
        ],
    },
    "esp32-s3": {
        "chip_family": "ESP32-S3 (QFN56)",
        "chip_revision": 2,
        "mac_address": "84:f7:03:a1:b2:c3",
        "crystal_freq": "40MHz",
        "features": ["Wi-Fi", "BLE 5.0", "Dual Core", "Vector Instructions"],
        "flash_size": "8MB",
        "flash_vendor_id": "0xc8 (GigaDevice)",
        "flash_mode": "DIO",
        "flash_speed": "80MHz",
        "sdk_version": "UNAVAILABLE_VIA_BOOTLOADER",
        "notes": [
            "Retrieved via non-destructive esptool flash-id query.",
            "SDK version requires firmware image analysis or UART boot log capture.",
        ],
    },
    "esp32-c3": {
        "chip_family": "ESP32-C3 (RISC-V)",
        "chip_revision": 3,
        "mac_address": "60:55:f9:1a:2b:3c",
        "crystal_freq": "40MHz",
        "features": ["Wi-Fi", "BLE 5.0", "Single Core RISC-V"],
        "flash_size": "4MB",
        "flash_vendor_id": "0x68 (Boya)",
        "flash_mode": "DIO",
        "flash_speed": "40MHz",
        "sdk_version": "UNAVAILABLE_VIA_BOOTLOADER",
        "notes": [
            "Retrieved via non-destructive esptool flash-id query.",
            "SDK version requires firmware image analysis or UART boot log capture.",
        ],
    },
}


def parse_esptool_output(output: str, port: str) -> IdentificationResult:
    """
    Parses esptool stdout into a structured, validated IdentificationResult.
    Extracts chip type, revision, MAC, crystal, and flash parameters honestly.
    """
    # 1. Check for Permission Denied
    if "permission denied" in output.lower() or "errno 13" in output.lower():
        return IdentificationResult(
            status=IdentificationStatus.PERMISSION_DENIED,
            port=port,
            warnings=[
                f"Permission denied accessing {port}. On Linux, ensure user is in 'dialout' group: "
                "'sudo usermod -aG dialout $USER'"
            ],
            raw_output=output,
        )

    # 2. Check for Port Busy / Locked
    if "port is busy" in output.lower() or "resource temporarily unavailable" in output.lower():
        return IdentificationResult(
            status=IdentificationStatus.PORT_BUSY,
            port=port,
            warnings=[
                f"Port {port} is currently locked or in use by another application "
                "(e.g., serial monitor, screen, minicom, or another esptool process)."
            ],
            raw_output=output,
        )

    # 3. Check for Connection Timeout / No Sync
    if "failed to connect" in output.lower() or "no serial data received" in output.lower():
        return IdentificationResult(
            status=IdentificationStatus.TIMEOUT,
            port=port,
            warnings=[
                f"Timed out synchronizing with ESP32 bootloader on {port}. "
                "Ensure board is powered, USB cable supports data, and press the BOOT button if auto-reset failed."
            ],
            raw_output=output,
        )

    # 4. Check for Chip identification
    chip_match = re.search(r"Chip is ([^\n\r]+)", output)
    if not chip_match:
        chip_match = re.search(r"Detecting chip type\.\.\. ([^\n\r]+)", output)

    if not chip_match:
        return IdentificationResult(
            status=IdentificationStatus.UNRECOGNIZED_DEVICE,
            port=port,
            warnings=[f"Device on {port} responded to serial but could not be identified as a supported ESP32."],
            raw_output=output,
        )

    chip_family = chip_match.group(1).strip()

    # Extract Revision
    chip_rev = None
    rev_match = re.search(r"revision v?([0-9]+)", output, re.IGNORECASE)
    if rev_match:
        try:
            chip_rev = int(rev_match.group(1))
        except ValueError:
            chip_rev = None

    # Extract MAC Address
    mac = None
    mac_match = re.search(r"MAC:\s*([0-9a-fA-F:]{17})", output)
    if mac_match:
        mac = mac_match.group(1).lower()

    # Extract Features
    features: List[str] = []
    feat_match = re.search(r"Features:\s*([^\n\r]+)", output)
    if feat_match:
        features = [f.strip() for f in feat_match.group(1).split(",") if f.strip()]

    # Extract Crystal
    crystal = None
    cryst_match = re.search(r"Crystal is\s*([0-9]+MHz)", output, re.IGNORECASE)
    if cryst_match:
        crystal = cryst_match.group(1)

    # Extract Flash Size
    flash_size = None
    flash_size_match = re.search(r"Detected flash size:\s*([0-9]+[MK]B)", output, re.IGNORECASE)
    if flash_size_match:
        flash_size = flash_size_match.group(1).upper()

    # Extract Manufacturer / Device ID
    vendor_id = None
    mfg_match = re.search(r"Manufacturer:\s*([0-9a-fA-Fx]+)", output)
    dev_match = re.search(r"Device:\s*([0-9a-fA-Fx]+)", output)
    if mfg_match:
        vendor_id = mfg_match.group(1)
        if dev_match:
            vendor_id = f"{vendor_id} (Device: {dev_match.group(1)})"

    notes = [
        "Retrieved via non-destructive esptool flash-id query.",
        "SDK version is unavailable via ROM bootloader interrogation.",
    ]

    return IdentificationResult(
        status=IdentificationStatus.SUCCESS,
        port=port,
        chip_family=chip_family,
        chip_revision=chip_rev,
        mac_address=mac,
        crystal_freq=crystal,
        features=features,
        flash_size=flash_size,
        flash_vendor_id=vendor_id,
        flash_mode="Unavailable (requires image header inspection)",
        flash_speed="Unavailable (requires image header inspection)",
        sdk_version="UNAVAILABLE_VIA_BOOTLOADER",
        warnings=[],
        notes=notes,
        raw_output=output,
    )


def identify_esp32_device(
    port: str,
    baudrate: int = 115200,
    timeout_seconds: float = 3.0,
    force_mock: bool = False,
    mock_chip: str = "esp32",
) -> IdentificationResult:
    """
    Performs safe, non-destructive ESP32 device interrogation.
    Strictly restricted to read-only queries (flash-id, read-mac, chip-id).
    Never performs flash write, erase, eFuse modification, or destructive resets.
    """
    # 1. Handle Synthetic Mock Mode for offline demonstrations & testing
    if force_mock:
        profile = MOCK_PROFILES.get(mock_chip.lower(), MOCK_PROFILES["esp32"])
        return IdentificationResult(
            status=IdentificationStatus.SUCCESS,
            port=port,
            chip_family=profile["chip_family"],
            chip_revision=profile["chip_revision"],
            mac_address=profile["mac_address"],
            crystal_freq=profile["crystal_freq"],
            features=profile["features"],
            flash_size=profile["flash_size"],
            flash_vendor_id=profile["flash_vendor_id"],
            flash_mode=profile["flash_mode"],
            flash_speed=profile["flash_speed"],
            sdk_version=profile["sdk_version"],
            warnings=[],
            notes=profile["notes"],
            raw_output="[SYNTHETIC TEST INTERROGATION OUTPUT]",
        )

    # 2. Build Safe Subprocess Argument List
    # NEVER invoke shell=True or concatenate unvalidated strings
    cmd = [
        sys.executable,
        "-m",
        "esptool",
        "--port",
        port,
        "--baud",
        str(baudrate),
        "--connect-attempts",
        "2",
        "--after",
        "no-reset",
        "flash-id",
    ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        return parse_esptool_output(proc.stdout, port)
    except subprocess.TimeoutExpired:
        return IdentificationResult(
            status=IdentificationStatus.TIMEOUT,
            port=port,
            warnings=[
                f"Connection attempt to {port} timed out after {timeout_seconds} seconds. "
                "The board did not respond to serial bootloader synchronization."
            ],
        )
    except PermissionError:
        return IdentificationResult(
            status=IdentificationStatus.PERMISSION_DENIED,
            port=port,
            warnings=[f"Permission denied accessing port {port}. Please verify user group permissions."],
        )
    except Exception as e:
        return IdentificationResult(
            status=IdentificationStatus.FAILED,
            port=port,
            warnings=[f"Unexpected error communicating with device on {port}: {type(e).__name__}"],
        )


def persist_device_record(db: Session, result: IdentificationResult) -> Optional[DeviceRecord]:
    """
    Persists or updates an identified ESP32 device record in SQLite.
    Prevents duplicate records when the same physical board is identified repeatedly.
    Does NOT persist failed or unrecognized connection attempts.
    """
    if result.status != IdentificationStatus.SUCCESS:
        return None

    # Check for existing device record by MAC address or Port
    existing = None
    if result.mac_address:
        existing = db.query(DeviceRecord).filter(DeviceRecord.mac_address == result.mac_address).first()
    if not existing and result.port:
        existing = db.query(DeviceRecord).filter(DeviceRecord.port == result.port).first()

    if existing:
        existing.port = result.port
        existing.chip_family = result.chip_family
        existing.chip_revision = result.chip_revision
        existing.flash_size = result.flash_size
        existing.flash_vendor_id = result.flash_vendor_id
        existing.crystal_freq = result.crystal_freq
        existing.notes = result.notes
        db.commit()
        db.refresh(existing)
        return existing

    device = DeviceRecord(
        port=result.port,
        chip_family=result.chip_family,
        chip_revision=result.chip_revision,
        mac_address=result.mac_address,
        crystal_freq=result.crystal_freq,
        flash_size=result.flash_size,
        flash_vendor_id=result.flash_vendor_id,
        flash_mode=result.flash_mode,
        flash_speed=result.flash_speed,
        sdk_version=result.sdk_version,
        notes=result.notes,
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    return device
