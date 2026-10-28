from typing import Optional, List
from pydantic import BaseModel, Field
from datetime import datetime


class SerialPortInfo(BaseModel):
    device: str
    name: str
    description: str
    hwid: str
    manufacturer: Optional[str] = None
    vid: Optional[str] = None
    pid: Optional[str] = None
    is_likely_esp: bool = False


class PortsResponse(BaseModel):
    ports: List[SerialPortInfo]


class DeviceIdentifyRequest(BaseModel):
    port: str = Field(..., description="Serial port path e.g. /dev/ttyUSB0")
    baudrate: int = Field(115200, description="Communication baudrate")
    timeout_seconds: float = Field(3.0, ge=1.0, le=15.0, description="Timeout in seconds")
    force_mock: bool = Field(False, description="Set True to simulate device interrogation for demonstration")


class DeviceIdentifyData(BaseModel):
    port: str
    chip_family: str
    chip_revision: Optional[int] = None
    mac_address: Optional[str] = None
    crystal_freq: Optional[str] = None
    flash_size: Optional[str] = None
    flash_vendor_id: Optional[str] = None
    flash_mode: Optional[str] = None
    flash_speed: Optional[str] = None
    sdk_version: Optional[str] = None
    notes: List[str] = Field(default_factory=list)


class DeviceIdentifyResponse(BaseModel):
    status: str
    device: DeviceIdentifyData
