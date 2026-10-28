from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from backend.app.config import settings
from backend.app.database import init_db
from backend.app.routers.health import router as health_router
from backend.app.routers.firmware import router as firmware_router
from backend.app.routers.device import router as device_router
from backend.app.routers.assessment import router as assessment_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database and upgrade schema
    init_db()
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=settings.app_description,
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include core routers
app.include_router(health_router)
app.include_router(firmware_router)
app.include_router(device_router)
app.include_router(assessment_router)


# Friendly redirect for /dashboard without trailing slash
@app.get("/dashboard", include_in_schema=False)
def dashboard_redirect():
    return RedirectResponse(url="/dashboard/", status_code=307)


# Mount frontend static files
frontend_dir = Path(__file__).resolve().parent.parent.parent / "frontend"
if frontend_dir.is_dir():
    app.mount("/dashboard", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")


@app.get("/")
def root(request: Request):
    accept = request.headers.get("accept", "")
    if "text/html" in accept and "application/json" not in accept:
        return RedirectResponse(url="/dashboard/", status_code=307)
    return {
        "message": f"Welcome to {settings.app_name} API",
        "version": settings.app_version,
        "docs_url": "/docs",
        "dashboard_url": "/dashboard/",
    }
