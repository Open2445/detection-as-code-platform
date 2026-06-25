"""FastAPI application entry point."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import create_tables
from app.routers import logs, rules, detections, alerts, dashboard

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown events."""
    # ── Startup ──────────────────────────────────────────────────────────
    logger.info("Starting Detection-as-Code Platform v%s", settings.app_version)
    create_tables()
    logger.info("Database tables created/verified")

    if settings.seed_on_startup:
        try:
            from seed.seed import run_seed
            run_seed()
            logger.info("Database seeded successfully")
        except Exception as exc:
            logger.warning("Seeding skipped or partially failed: %s", exc)

    yield

    # ── Shutdown ─────────────────────────────────────────────────────────
    logger.info("Shutting down Detection-as-Code Platform")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "A Detection-as-Code platform for security analysts. "
        "Upload Windows/Sysmon JSON logs, run Sigma detection rules, "
        "generate alerts mapped to MITRE ATT&CK."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(logs.router, prefix="/api/logs", tags=["Logs"])
app.include_router(rules.router, prefix="/api/rules", tags=["Rules"])
app.include_router(detections.router, prefix="/api/detections", tags=["Detections"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])


@app.get("/health", tags=["Health"])
def health_check():
    """Health check endpoint for Docker/load balancer."""
    return {"status": "ok", "version": settings.app_version}
