from backend.app.routers.health import router as health_router
from backend.app.routers.firmware import router as firmware_router
from backend.app.routers.device import router as device_router
from backend.app.routers.assessment import router as assessment_router

__all__ = ["health_router", "firmware_router", "device_router", "assessment_router"]
