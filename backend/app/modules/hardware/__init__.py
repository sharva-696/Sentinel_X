from backend.app.modules.hardware.serial_discovery import discover_serial_ports, SerialPortMetadata
from backend.app.modules.hardware.esp32_identification import (
    identify_esp32_device,
    IdentificationResult,
    IdentificationStatus,
)

__all__ = [
    "discover_serial_ports",
    "SerialPortMetadata",
    "identify_esp32_device",
    "IdentificationResult",
    "IdentificationStatus",
]
