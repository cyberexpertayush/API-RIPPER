"""
API RIPPER — Main Application Entry Point
FastAPI server wrapping ARSec security scanner engine
"""

import asyncio
import logging
import sys
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.config import get_settings
from backend.database import init_database

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management"""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")

    try:
        db_manager = init_database()
        app.state.db_manager = db_manager
        logger.info("✓ Database initialized")
    except Exception as e:
        logger.error(f"✗ Startup failed: {e}")
        sys.exit(1)

    yield

    logger.info("Shutting down...")
    if hasattr(app.state, 'db_manager'):
        app.state.db_manager.close()
    logger.info("✓ Shutdown complete")


def create_app() -> FastAPI:
    """Create and configure FastAPI application"""

    app = FastAPI(
        title=settings.APP_NAME,
        description="API RIPPER — Advanced API Security Scanner powered by ARSec Engine",
        version=settings.APP_VERSION,
        docs_url="/docs",
        openapi_url="/openapi.json",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ============================================================
    # INLINE ROUTES
    # ============================================================

    @app.get("/health")
    async def health_check():
        return {
            "status": "healthy",
            "app": settings.APP_NAME,
            "version": settings.APP_VERSION,
        }

    @app.get("/")
    async def root():
        return {
            "message": f"Welcome to {settings.APP_NAME}",
            "version": settings.APP_VERSION,
            "engine": "ARSec v3.8",
            "documentation": f"http://{settings.API_HOST}:{settings.API_PORT}/docs",
            "api_version": "v1",
        }

    # ============================================================
    # ROUTE INCLUDES
    # ============================================================

    from backend.routes.scans import router as scans_router
    app.include_router(scans_router, prefix="/api/v1", tags=["Scans"])

    from backend.routes.findings import router as findings_router
    app.include_router(findings_router, prefix="/api/v1", tags=["Findings"])

    from backend.routes.reports import router as reports_router
    app.include_router(reports_router, prefix="/api/v1", tags=["Reports"])

    from backend.routes.comparison import router as comparison_router
    app.include_router(comparison_router, prefix="/api/v1", tags=["Comparison"])

    try:
        from backend.routes.websocket import router as ws_router
        app.include_router(ws_router, tags=["WebSocket"])
        logger.info("✓ WebSocket routes registered")
    except ImportError:
        logger.warning("⚠ WebSocket routes not available")

    # ============================================================
    # ERROR HANDLER
    # ============================================================

    @app.exception_handler(Exception)
    async def general_exception_handler(request, exc):
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )

    return app


app = create_app()


if __name__ == "__main__":
    logger.info(f"Starting {settings.APP_NAME}")
    logger.info(f"API Server: http://{settings.API_HOST}:{settings.API_PORT}")
    logger.info(f"Documentation: http://{settings.API_HOST}:{settings.API_PORT}/docs")

    uvicorn.run(
        "backend.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        workers=1,
        reload=settings.API_RELOAD,
        log_level=settings.LOG_LEVEL.lower(),
    )
