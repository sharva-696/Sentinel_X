import os
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

try:
    import serial.tools.list_ports
    PYSERIAL_AVAILABLE = True
except ImportError:
    PYSERIAL_AVAILABLE = False


# Known USB-to-UART bridge Vendor IDs and Product IDs common in ESP32 dev boards
KNOWN_ESP_VID_PIDS = [
    # Silicon Labs CP210x (NodeMCU, ESP32 DevKitC)
    ("10c4", "ea60"),
    ("10c4", "ea70"),
    ("10c4", "ea71"),
    # FTDI FT232R / FT2232H
    ("0403", "6001"),
    ("0403", "6010"),
    ("0403", "6011"),
    ("0403", "6015"),
    # WCH CH340 / CH341 / CH9102 (Popular cheap dev boards)
    ("1a86", "7523"),
    ("1a86", "5523"),
    ("1a86", "55d4"),
    ("1a86", "55d3"),
    # Espressif Built-in USB JTAG/Serial (ESP32-S3, ESP32-C3, ESP32-C6)
    ("303a", "1001"),
    ("303a", "1002"),
    ("303a", "0002"),
]


class SerialPortMetadata(BaseModel):
    device: str = Field(..., description="Operating system device path e.g. /dev/ttyUSB0")
    name: str = Field(..., description="Short device name e.g. ttyUSB0")
    description: str = Field(..., description="Human-readable port description")
    hwid: str = Field("n/a", description="Hardware identifier string")
    manufacturer: Optional[str] = None
    product: Optional[str] = None
    serial_number: Optional[str] = None
    vid: Optional[str] = None
    pid: Optional[str] = None
    interface: Optional[str] = None
    is_usb_adapter: bool = False
    is_likely_esp: bool = False
    is_accessible: bool = True
    permission_warning: Optional[str] = None


def check_port_access(port_path: str) -> tuple[bool, Optional[str]]:
    """
    Checks if the current process has read/write permissions on the serial port.
    Returns (is_accessible, permission_warning).
    """
    if not os.path.exists(port_path):
        return False, f"Device node {port_path} does not exist."

    # Test read and write permissions without locking
    can_read = os.access(port_path, os.R_OK)
    can_write = os.access(port_path, os.W_OK)

    if can_read and can_write:
        return True, None

    warning = (
        f"Permission denied accessing {port_path}. "
        "On Linux systems, your user must be a member of the 'dialout' or 'uucp' group. "
        "Run: 'sudo usermod -aG dialout $USER' and log back in."
    )
    return False, warning


def discover_serial_ports() -> List[SerialPortMetadata]:
    """
    Enumerates available serial ports using pySerial and returns structured metadata.
    Does not modify system permissions or execute privileged operations.
    """
    if not PYSERIAL_AVAILABLE:
        return []

    discovered: List[SerialPortMetadata] = []
    ports = list(serial.tools.list_ports.comports())

    for p in ports:
        device_path = p.device
        name = p.name or os.path.basename(device_path)
        desc = p.description or "Unknown Serial Port"
        hwid = p.hwid or "n/a"
        manufacturer = p.manufacturer
        product = p.product
        serial_num = p.serial_number
        interface = p.interface

        vid_hex = f"{p.vid:04x}".lower() if p.vid is not None else None
        pid_hex = f"{p.pid:04x}".lower() if p.pid is not None else None

        # Determine if it's a USB serial adapter
        is_usb = bool(
            p.vid is not None
            or "usb" in hwid.lower()
            or "ttyusb" in device_path.lower()
            or "ttyacm" in device_path.lower()
            or "ch340" in desc.lower()
            or "cp210" in desc.lower()
            or "ftdi" in desc.lower()
        )

        # Determine if it matches known ESP32 bridge chips
        is_likely_esp = False
        if vid_hex and pid_hex:
            if (vid_hex, pid_hex) in KNOWN_ESP_VID_PIDS:
                is_likely_esp = True
        if "espressif" in (manufacturer or "").lower() or "espressif" in desc.lower():
            is_likely_esp = True

        # Check Linux device permissions
        is_accessible, perm_warning = check_port_access(device_path)

        metadata = SerialPortMetadata(
            device=device_path,
            name=name,
            description=desc,
            hwid=hwid,
            manufacturer=manufacturer,
            product=product,
            serial_number=serial_num,
            vid=f"0x{vid_hex}" if vid_hex else None,
            pid=f"0x{pid_hex}" if pid_hex else None,
            interface=interface,
            is_usb_adapter=is_usb,
            is_likely_esp=is_likely_esp,
            is_accessible=is_accessible,
            permission_warning=perm_warning,
        )
        discovered.append(metadata)

    return discovered
