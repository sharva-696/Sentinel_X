from pydantic import BaseModel


class ToolStatus(BaseModel):
    esptool_available: bool
    pyserial_available: bool
    binwalk_available: bool
    reportlab_available: bool


class EnvironmentInfo(BaseModel):
    os: str
    python_version: str


class HealthResponse(BaseModel):
    status: str
    app_name: str
    version: str
    database_connected: bool
    environment: EnvironmentInfo
    tools: ToolStatus
