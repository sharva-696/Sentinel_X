from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.config import settings
from backend.app.database import init_db
from backend.app.routers.health import router as health_router
from backend.app.routers.firmware import router as firmware_router
from backend.app.routers.device import router as device_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database and tables
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


@app.get("/")
def root():
    return {
        "message": f"Welcome to {settings.app_name} API",
        "version": settings.app_version,
        "docs_url": "/docs",
    }
