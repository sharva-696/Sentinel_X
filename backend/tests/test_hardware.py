from unittest.mock import patch, MagicMock
import subprocess
import pytest
from fastapi.testclient import TestClient

from backend.app.modules.hardware.serial_discovery import (
    discover_serial_ports,
    SerialPortMetadata,
    check_port_access,
)
from backend.app.modules.hardware.esp32_identification import (
    identify_esp32_device,
    parse_esptool_output,
    persist_device_record,
    IdentificationStatus,
    IdentificationResult,
)
from backend.app.models.device import DeviceRecord


class MockListPortInfo:
    """Mock object mimicking serial.tools.list_ports.ListPortInfo."""
    def __init__(
        self,
        device="/dev/ttyUSB0",
        name="ttyUSB0",
        description="CP2102 USB to UART Bridge Controller",
        hwid="USB VID:PID=10C4:EA60",
        vid=0x10C4,
        pid=0xEA60,
        manufacturer="Silicon Labs",
        product="CP2102 USB to UART Bridge",
        serial_number="0001",
        interface=None,
    ):
        self.device = device
        self.name = name
        self.description = description
        self.hwid = hwid
        self.vid = vid
        self.pid = pid
        self.manufacturer = manufacturer
        self.product = product
        self.serial_number = serial_number
        self.interface = interface


# =========================================================================
# 1. Port Discovery Tests
# =========================================================================

def test_discover_serial_ports_none_detected():
    with patch("serial.tools.list_ports.comports", return_value=[]):
        ports = discover_serial_ports()
        assert len(ports) == 0


def test_discover_serial_ports_single_port():
    mock_port = MockListPortInfo(
        device="/dev/ttyUSB0",
        name="ttyUSB0",
        description="CP2102 USB to UART",
        vid=0x10C4,
        pid=0xEA60,
        manufacturer="Silicon Labs",
    )
    with patch("serial.tools.list_ports.comports", return_value=[mock_port]):
        ports = discover_serial_ports()
        assert len(ports) == 1
        p = ports[0]
        assert p.device == "/dev/ttyUSB0"
        assert p.name == "ttyUSB0"
        assert p.vid == "0x10c4"
        assert p.pid == "0xea60"
        assert p.is_usb_adapter is True
        assert p.is_likely_esp is True


def test_discover_serial_ports_multiple_ports():
    mock_esp = MockListPortInfo(
        device="/dev/ttyACM0",
        name="ttyACM0",
        description="Espressif USB JTAG/serial debug unit",
        vid=0x303A,
        pid=0x1001,
        manufacturer="Espressif",
    )
    mock_generic = MockListPortInfo(
        device="/dev/ttyS0",
        name="ttyS0",
        description="Standard Serial Port",
        hwid="n/a",
        vid=None,
        pid=None,
        manufacturer=None,
    )
    with patch("serial.tools.list_ports.comports", return_value=[mock_esp, mock_generic]):
        ports = discover_serial_ports()
        assert len(ports) == 2
        esp_p = next(p for p in ports if p.device == "/dev/ttyACM0")
        gen_p = next(p for p in ports if p.device == "/dev/ttyS0")
        assert esp_p.is_likely_esp is True
        assert gen_p.is_likely_esp is False


def test_discover_serial_ports_missing_usb_metadata():
    """Handles ports where VID, PID, manufacturer, and serial numbers are None."""
    bare_port = MockListPortInfo(
        device="/dev/ttyUSB1",
        name="ttyUSB1",
        description="Generic Serial",
        hwid="n/a",
        vid=None,
        pid=None,
        manufacturer=None,
        product=None,
        serial_number=None,
    )
    with patch("serial.tools.list_ports.comports", return_value=[bare_port]):
        ports = discover_serial_ports()
        assert len(ports) == 1
        p = ports[0]
        assert p.vid is None
        assert p.pid is None
        assert p.manufacturer is None
        assert p.is_usb_adapter is True  # Inferred from ttyUSB in name


def test_check_port_access_guidance():
    with patch("os.path.exists", return_value=True), patch("os.access", return_value=False):
        accessible, warning = check_port_access("/dev/ttyUSB0")
        assert accessible is False
        assert "dialout" in warning
        assert "sudo usermod -aG dialout" in warning


# =========================================================================
# 2. Non-Destructive ESP32 Identification Tests
# =========================================================================

REALISTIC_ESP32_OUTPUT = """
esptool v5.6.0
Serial port /dev/ttyUSB0
Connecting....
Detecting chip type... ESP32-S3
Chip is ESP32-S3 (QFN56) (revision v0.2)
Features: WiFi, BLE
Crystal is 40MHz
MAC: 84:f7:03:a1:b2:c3
Uploading stub...
Running stub...
Stub running...
Manufacturer: c8
Device: 4017
Detected flash size: 8MB
Hard resetting via RTS pin...
"""

def test_parse_esptool_output_success():
    result = parse_esptool_output(REALISTIC_ESP32_OUTPUT, "/dev/ttyUSB0")
    assert result.status == IdentificationStatus.SUCCESS
    assert result.port == "/dev/ttyUSB0"
    assert "ESP32-S3" in result.chip_family
    assert result.mac_address == "84:f7:03:a1:b2:c3"
    assert result.flash_size == "8MB"
    assert result.crystal_freq == "40MHz"
    assert result.flash_vendor_id == "c8 (Device: 4017)"
    assert result.sdk_version == "UNAVAILABLE_VIA_BOOTLOADER"
    assert len(result.warnings) == 0


def test_parse_esptool_output_timeout():
    timeout_output = """
esptool v5.6.0
Serial port /dev/ttyUSB0
Connecting......................................
A fatal error occurred: Failed to connect to ESP32: No serial data received.
For troubleshooting steps see: https://docs.espressif.com/...
"""
    result = parse_esptool_output(timeout_output, "/dev/ttyUSB0")
    assert result.status == IdentificationStatus.TIMEOUT
    assert len(result.warnings) > 0
    assert "Timed out" in result.warnings[0]


def test_parse_esptool_output_permission_denied():
    perm_output = """
esptool v5.6.0
Serial port /dev/ttyUSB0
[Errno 13] could not open port /dev/ttyUSB0: [Errno 13] Permission denied: '/dev/ttyUSB0'
"""
    result = parse_esptool_output(perm_output, "/dev/ttyUSB0")
    assert result.status == IdentificationStatus.PERMISSION_DENIED
    assert "dialout" in result.warnings[0]


def test_parse_esptool_output_port_busy():
    busy_output = """
esptool v5.6.0
Serial port /dev/ttyUSB0:
Could not open /dev/ttyUSB0, the port is busy or doesn't exist.
(Could not configure port: (16, 'Device or resource busy'))
"""
    result = parse_esptool_output(busy_output, "/dev/ttyUSB0")
    assert result.status == IdentificationStatus.PORT_BUSY
    assert "locked or in use" in result.warnings[0]


def test_parse_esptool_output_unrecognized_device():
    unrec_output = """
esptool v5.6.0
Serial port /dev/ttyUSB0
Connecting....
A fatal error occurred: Unexpected response from serial device.
"""
    result = parse_esptool_output(unrec_output, "/dev/ttyUSB0")
    assert result.status == IdentificationStatus.UNRECOGNIZED_DEVICE
    assert "could not be identified as a supported ESP32" in result.warnings[0]


def test_identify_esp32_device_mock_mode():
    """Validates synthetic mock mode profiles (esp32, esp32-s3, esp32-c3)."""
    res_s3 = identify_esp32_device("/dev/ttyUSB0", force_mock=True, mock_chip="esp32-s3")
    assert res_s3.status == IdentificationStatus.SUCCESS
    assert "ESP32-S3" in res_s3.chip_family
    assert res_s3.flash_size == "8MB"

    res_c3 = identify_esp32_device("/dev/ttyUSB1", force_mock=True, mock_chip="esp32-c3")
    assert res_c3.status == IdentificationStatus.SUCCESS
    assert "ESP32-C3" in res_c3.chip_family
    assert res_c3.flash_size == "4MB"


def test_identify_esp32_device_timeout_handling():
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="esptool", timeout=3.0)):
        res = identify_esp32_device("/dev/ttyUSB0", timeout_seconds=3.0)
        assert res.status == IdentificationStatus.TIMEOUT
        assert "timed out" in res.warnings[0]


def test_safety_guarantee_no_destructive_commands_invoked():
    """
    Rigorously verifies that identify_esp32_device only executes non-destructive commands.
    It must never execute write_flash, erase_flash, erase_region, or burn_efuse.
    """
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=REALISTIC_ESP32_OUTPUT, returncode=0)
        identify_esp32_device("/dev/ttyUSB0")

        assert mock_run.called
        invoked_cmd = mock_run.call_args[0][0]

        # Verify command arguments list
        assert isinstance(invoked_cmd, list)
        assert "flash-id" in invoked_cmd
        assert "no-reset" in invoked_cmd

        # Assert absence of any destructive commands
        prohibited_commands = [
            "write_flash",
            "write-flash",
            "erase_flash",
            "erase-flash",
            "erase_region",
            "erase-region",
            "burn_efuse",
            "burn-efuse",
        ]
        for prohibited in prohibited_commands:
            assert prohibited not in invoked_cmd, f"Destructive command detected: {prohibited}"


# =========================================================================
# 3. Database Persistence Tests
# =========================================================================

def test_persist_device_record_idempotent_no_duplicates(db_session):
    result = IdentificationResult(
        status=IdentificationStatus.SUCCESS,
        port="/dev/ttyUSB0",
        chip_family="ESP32-S3",
        chip_revision=2,
        mac_address="84:f7:03:a1:b2:c3",
        crystal_freq="40MHz",
        flash_size="8MB",
        flash_vendor_id="0xc8",
        notes=["First query"],
    )

    # 1. First persistence
    dev1 = persist_device_record(db_session, result)
    assert dev1 is not None
    dev1_id = dev1.id

    # 2. Second persistence with updated notes
    result.notes = ["Second query"]
    dev2 = persist_device_record(db_session, result)
    assert dev2 is not None
    assert dev2.id == dev1_id  # ID must remain identical

    # Check total count in database
    count = db_session.query(DeviceRecord).filter(DeviceRecord.mac_address == "84:f7:03:a1:b2:c3").count()
    assert count == 1


def test_do_not_persist_failed_identifications(db_session):
    result_timeout = IdentificationResult(
        status=IdentificationStatus.TIMEOUT,
        port="/dev/ttyUSB0",
        warnings=["Timed out"],
    )
    dev = persist_device_record(db_session, result_timeout)
    assert dev is None
    assert db_session.query(DeviceRecord).count() == 0


# =========================================================================
# 4. API Endpoints Integration Tests
# =========================================================================

def test_api_get_devices_ports(client: TestClient):
    mock_port = MockListPortInfo(device="/dev/ttyUSB0", name="ttyUSB0", vid=0x10C4, pid=0xEA60)
    with patch("serial.tools.list_ports.comports", return_value=[mock_port]):
        res = client.get("/api/devices/ports")
        assert res.status_code == 200
        data = res.json()
        assert data["total_ports"] == 1
        assert data["ports"][0]["device"] == "/dev/ttyUSB0"
        assert data["ports"][0]["is_likely_esp"] is True


def test_api_post_identify_device_mock(client: TestClient):
    payload = {
        "port": "/dev/ttyUSB0",
        "baudrate": 115200,
        "timeout_seconds": 3.0,
        "force_mock": True,
        "mock_chip": "esp32-s3",
    }
    res = client.post("/api/devices/identify", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["persisted"] is True
    assert "ESP32-S3" in data["device"]["chip_family"]
    assert data["device"]["flash_size"] == "8MB"


def test_api_post_identify_device_invalid_port_injection(client: TestClient):
    """Rejects port inputs containing shell metacharacters with HTTP 400."""
    payload = {
        "port": "/dev/ttyUSB0; rm -rf /",
        "baudrate": 115200,
        "timeout_seconds": 3.0,
        "force_mock": False,
    }
    res = client.post("/api/devices/identify", json=payload)
    assert res.status_code == 400
    assert "invalid serial port" in res.json()["detail"].lower()


def test_api_get_devices_list(client: TestClient):
    # Perform mock identify to ensure at least 1 device is saved
    client.post(
        "/api/devices/identify",
        json={"port": "/dev/ttyUSB0", "force_mock": True, "mock_chip": "esp32"},
    )
    res = client.get("/api/devices")
    assert res.status_code == 200
    data = res.json()
    assert data["total_devices"] >= 1
    assert data["devices"][0]["port"] == "/dev/ttyUSB0"
