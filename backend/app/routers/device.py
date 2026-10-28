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
)
from backend.app.modules.hardware.serial_discovery import discover_serial_ports
from backend.app.modules.hardware.esp32_identification import (
    identify_esp32_device,
    persist_device_record,
    IdentificationStatus,
)

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
