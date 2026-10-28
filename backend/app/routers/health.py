import os
import sys
import platform
import shutil
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from backend.app.database import get_db
from backend.app.config import settings
from backend.app.schemas.health import HealthResponse, ToolStatus, EnvironmentInfo

router = APIRouter(prefix="/api", tags=["Health"])


def check_tool_availability() -> ToolStatus:
    # Check esptool
    esptool_ok = False
    try:
        import esptool  # noqa: F401
        esptool_ok = True
    except ImportError:
        esptool_ok = shutil.which("esptool.py") is not None or shutil.which("esptool") is not None

    # Check pyserial
    serial_ok = False
    try:
        import serial  # noqa: F401
        serial_ok = True
    except ImportError:
        serial_ok = False

    # Check binwalk
    binwalk_ok = False
    try:
        import binwalk  # noqa: F401
        binwalk_ok = True
    except ImportError:
        binwalk_ok = shutil.which("binwalk") is not None

    # Check reportlab
    reportlab_ok = False
    try:
        import reportlab  # noqa: F401
        reportlab_ok = True
    except ImportError:
        reportlab_ok = False

    return ToolStatus(
        esptool_available=esptool_ok,
        pyserial_available=serial_ok,
        binwalk_available=binwalk_ok,
        reportlab_available=reportlab_ok,
    )


@router.get("/health", response_model=HealthResponse)
def get_health(db: Session = Depends(get_db)):
    db_ok = False
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    env_info = EnvironmentInfo(
        os=f"{platform.system()} {platform.release()}",
        python_version=platform.python_version(),
    )

    tools = check_tool_availability()

    return HealthResponse(
        status="healthy" if db_ok else "degraded",
        app_name=settings.app_name,
        version=settings.app_version,
        database_connected=db_ok,
        environment=env_info,
        tools=tools,
    )
