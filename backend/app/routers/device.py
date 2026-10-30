import re
import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.device import DeviceRecord
from backend.app.schemas.device import (
    PortsResponse,
    SerialPortInfo,
    DeviceIdentifyRequest,
    DeviceIdentifyResponse,
    DeviceIdentifyData,
    DeviceRecordResponse,
    DeviceListResponse,
    DeviceDumpRequest,
    DeviceDeleteResponse,
)
from backend.app.modules.hardware.serial_discovery import discover_serial_ports
from backend.app.modules.hardware.esp32_identification import (
    identify_esp32_device,
    persist_device_record,
    dump_esp32_flash,
    IdentificationStatus,
)
from backend.app.modules.analysis.engine import analyze_firmware_bytes, persist_analysis_record

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Device Interrogation"])

# Whitelist safe characters for serial device paths
SAFE_PORT_REGEX = re.compile(r"^[a-zA-Z0-9_\-\./\\]+$")


def validate_port_string(port: str) -> None:
    if not port or not SAFE_PORT_REGEX.match(port):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid serial port path format. Special shell characters are strictly prohibited.",
        )


@router.get("/api/devices/ports", response_model=PortsResponse)
@router.get("/api/device/ports", response_model=PortsResponse)
def get_serial_ports():
    """
    Enumerates host serial ports, extracting USB VID/PID, descriptions,
    adapter classification, and Linux device node access permissions.
    """
    discovered = discover_serial_ports()
    port_infos = [
        SerialPortInfo(
            device=p.device,
            name=p.name,
            description=p.description,
            hwid=p.hwid,
            manufacturer=p.manufacturer,
            product=p.product,
            serial_number=p.serial_number,
            vid=p.vid,
            pid=p.pid,
            interface=p.interface,
            is_usb_adapter=p.is_usb_adapter,
            is_likely_esp=p.is_likely_esp,
            is_accessible=p.is_accessible,
            permission_warning=p.permission_warning,
        )
        for p in discovered
    ]
    return PortsResponse(total_ports=len(port_infos), ports=port_infos)


@router.post("/api/devices/identify", response_model=DeviceIdentifyResponse)
@router.post("/api/device/identify", response_model=DeviceIdentifyResponse)
def identify_device(req: DeviceIdentifyRequest, db: Session = Depends(get_db)):
    """
    Initiates safe, non-destructive interrogation on the selected serial port.
    Retrieves chip model, silicon revision, MAC, crystal, and flash silicon size.
    Never flashes, erases, modifies eFuses, or executes destructive operations.
    """
    validate_port_string(req.port)

    # Optional port check: unless in mock mode, check if port exists in OS
    if not req.force_mock:
        discovered = discover_serial_ports()
        available_ports = [p.device for p in discovered]
        if available_ports and req.port not in available_ports:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Selected port {req.port} was not found among detected serial ports.",
            )

    try:
        result = identify_esp32_device(
            port=req.port,
            baudrate=req.baudrate,
            timeout_seconds=req.timeout_seconds,
            force_mock=req.force_mock,
            mock_chip=req.mock_chip,
        )
    except Exception as e:
        logger.error(f"Error during device identification on {req.port}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unexpected error communicating with device.",
        )

    # Persist in SQLite only on successful identification
    saved_device = None
    if result.status == IdentificationStatus.SUCCESS:
        try:
            saved_device = persist_device_record(db, result)
        except Exception as e:
            logger.error(f"Failed to persist device record: {e}")
            db.rollback()

    device_data = DeviceIdentifyData(
        port=result.port,
        chip_family=result.chip_family,
        chip_revision=result.chip_revision,
        mac_address=result.mac_address,
        crystal_freq=result.crystal_freq,
        features=result.features,
        flash_size=result.flash_size,
        flash_vendor_id=result.flash_vendor_id,
        flash_mode=result.flash_mode,
        flash_speed=result.flash_speed,
        sdk_version=result.sdk_version,
        tool_version=result.tool_version,
        warnings=result.warnings,
        notes=result.notes,
    )

    return DeviceIdentifyResponse(
        status=result.status.value,
        device=device_data,
        persisted=saved_device is not None,
        device_id=saved_device.id if saved_device else None,
    )


@router.get("/api/devices", response_model=DeviceListResponse)
def list_devices(db: Session = Depends(get_db)):
    """Lists saved ESP32 device records from local SQLite database."""
    devices = db.query(DeviceRecord).order_by(DeviceRecord.created_at.desc()).all()
    records = [
        DeviceRecordResponse(
            id=d.id,
            port=d.port,
            chip_family=d.chip_family,
            chip_revision=d.chip_revision,
            mac_address=d.mac_address,
            crystal_freq=d.crystal_freq,
            flash_size=d.flash_size,
            flash_vendor_id=d.flash_vendor_id,
            flash_mode=d.flash_mode,
            flash_speed=d.flash_speed,
            sdk_version=d.sdk_version,
            notes=d.notes,
            created_at=d.created_at,
        )
        for d in devices
    ]
    return DeviceListResponse(total_devices=len(records), devices=records)


@router.get("/api/devices/{device_id}", response_model=DeviceRecordResponse)
def get_device(device_id: int, db: Session = Depends(get_db)):
    """Retrieves a specific device record by primary key."""
    device = db.query(DeviceRecord).filter(DeviceRecord.id == device_id).first()
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device record with ID {device_id} not found.",
        )
    return DeviceRecordResponse(
        id=device.id,
        port=device.port,
        chip_family=device.chip_family,
        chip_revision=device.chip_revision,
        mac_address=device.mac_address,
        crystal_freq=device.crystal_freq,
        flash_size=device.flash_size,
        flash_vendor_id=device.flash_vendor_id,
        flash_mode=device.flash_mode,
        flash_speed=device.flash_speed,
        sdk_version=device.sdk_version,
        notes=device.notes,
        created_at=device.created_at,
    )


@router.delete("/api/devices/{device_id}", response_model=DeviceDeleteResponse)
def delete_device(device_id: int, db: Session = Depends(get_db)):
    """Deletes an ESP32 hardware device record from local registry."""
    device = db.query(DeviceRecord).filter(DeviceRecord.id == device_id).first()
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device record with ID {device_id} not found.",
        )
    db.delete(device)
    db.commit()
    return DeviceDeleteResponse(
        success=True,
        message=f"Device record #{device_id} deleted successfully.",
        deleted_id=device_id,
    )


@router.post("/api/devices/dump-firmware", status_code=status.HTTP_200_OK)
@router.post("/api/device/dump-firmware", status_code=status.HTTP_200_OK)
def dump_device_firmware(req: DeviceDumpRequest, db: Session = Depends(get_db)):
    """
    Safely dumps SPI flash memory from a connected ESP32 board over serial,
    then automatically runs a complete static vulnerability analysis on the dumped binary.
    """
    validate_port_string(req.port)

    # Optional port presence verification
    if not req.force_mock:
        discovered = discover_serial_ports()
        available_ports = [p.device for p in discovered]
        if available_ports and req.port not in available_ports:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Port {req.port} not found among active system serial ports.",
            )

    success, msg, dump_path = dump_esp32_flash(
        port=req.port,
        baudrate=req.baudrate,
        flash_size_bytes=req.flash_size_bytes,
        timeout_seconds=req.timeout_seconds,
        force_mock=req.force_mock,
    )

    if not success or not dump_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=msg,
        )

    try:
        with open(dump_path, "rb") as f:
            file_bytes = f.read()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read dumped firmware artifact: {e}",
        )

    clean_name = f"dump_{req.port.replace('/', '_')}.bin"
    analysis_result = analyze_firmware_bytes(file_bytes, original_filename=clean_name)
    if req.device_id:
        analysis_result["device_id"] = req.device_id

    persist_analysis_record(db, analysis_result)
    return analysis_result

