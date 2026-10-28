from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime


class SerialPortInfo(BaseModel):
    device: str
    name: str
    description: str
    hwid: str
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


class PortsResponse(BaseModel):
    total_ports: int
    ports: List[SerialPortInfo]


class DeviceIdentifyRequest(BaseModel):
    port: str = Field(..., description="Serial port path e.g. /dev/ttyUSB0")
    baudrate: int = Field(115200, ge=9600, le=921600, description="Communication baudrate")
    timeout_seconds: float = Field(3.0, ge=1.0, le=15.0, description="Timeout in seconds")
    force_mock: bool = Field(False, description="Set True to simulate device interrogation for demonstration")
    mock_chip: str = Field("esp32", description="Synthetic chip profile: esp32, esp32-s3, esp32-c3")


class DeviceIdentifyData(BaseModel):
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
    tool_version: Optional[str] = None
    warnings: List[str] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)


class DeviceIdentifyResponse(BaseModel):
    status: str
    device: DeviceIdentifyData
    persisted: bool = False
    device_id: Optional[int] = None


class DeviceRecordResponse(BaseModel):
    id: int
    port: str
    chip_family: Optional[str] = None
    chip_revision: Optional[int] = None
    mac_address: Optional[str] = None
    crystal_freq: Optional[str] = None
    flash_size: Optional[str] = None
    flash_vendor_id: Optional[str] = None
    flash_mode: Optional[str] = None
    flash_speed: Optional[str] = None
    sdk_version: Optional[str] = None
    notes: Optional[List[str]] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class DeviceListResponse(BaseModel):
    total_devices: int
    devices: List[DeviceRecordResponse]
