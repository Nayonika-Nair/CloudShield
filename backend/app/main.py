# ============================================================
# CloudShield FastAPI application
# ============================================================
#
# Wires the legacy CloudShield routes, the Fake AWS simulator API,
# consistent error handling, health checks and safe start-up
# initialisation (schema creation and optional demo seeding).

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import inspect, text

from app import models  # noqa: F401  (registers every table on Base.metadata)
from app.auth import hash_password
from app.database import Base, SessionLocal, engine
from app.models import User
from app.routers import sim as sim_router
from app.routes import router as legacy_router
from app.simulator.env import SimError

log = logging.getLogger("cloudshield")


def ensure_schema() -> None:
    """Create missing tables and add columns introduced after the first release."""

    Base.metadata.create_all(bind=engine)
    columns = {c["name"] for c in inspect(engine).get_columns("users")}
    if "role" not in columns:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'viewer'"))


def seed_users() -> None:
    """Create accounts from environment variables. Nothing is hardcoded."""

    pairs = [("admin", "ADMIN"), ("analyst", "ANALYST"), ("viewer", "VIEWER")]
    with SessionLocal() as db:
        for role, prefix in pairs:
            email, password = os.getenv(f"{prefix}_EMAIL"), os.getenv(f"{prefix}_PASSWORD")
            if not email or not password:
                continue
            user = db.query(User).filter(User.email == email).first()
            if user is None:
                db.add(User(email=email, password_hash=hash_password(password), role=role))
            elif user.role != role:
                user.role = role
        db.commit()


def seed_demo_environment() -> None:
    """Generate the default demonstration environment on a fresh database."""

    from app.services import env_store, sim_service

    with SessionLocal() as db:
        if env_store.active_row(db) is None:
            sim_service.generate(db, "system", {}, preset="typical", name="demo-environment")


async def _auto_advance(interval: int) -> None:
    from app.services import env_store, sim_service

    while True:
        await asyncio.sleep(interval)
        try:
            with SessionLocal() as db:
                row = env_store.active_row(db)
                if row is not None and row.config["time"]["auto_advance"]:
                    sim_service.advance_time(db, "auto-advance", row.config["time"]["days_per_tick"])
        except Exception:  # keep the loop alive
            log.exception("auto-advance tick failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_schema()
    seed_users()
    if os.getenv("SEED_DEMO_ENVIRONMENT", "true").lower() == "true":
        seed_demo_environment()
    task = None
    interval = int(os.getenv("SIM_AUTO_ADVANCE_SECONDS", "0") or 0)
    if interval > 0:
        task = asyncio.create_task(_auto_advance(interval))
    yield
    if task:
        task.cancel()


app = FastAPI(
    title="CloudShield API",
    version="2.0.0",
    description=(
        "Cloud cost and security optimisation platform backed by a configurable, stateful Fake AWS simulator. "
        "No real AWS credentials are used and no real infrastructure is touched."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.getenv(
        "CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000,http://localhost:8000,http://127.0.0.1:8000"
    ).split(",") if o.strip()],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------------------------------------------
# Consistent error responses
# ------------------------------------------------------------

def _error(status: int, code: str, message: str, **extra) -> JSONResponse:
    return JSONResponse(status_code=status, content={"detail": message, "error": {"code": code, "message": message, **extra}})


@app.exception_handler(SimError)
async def sim_error_handler(_: Request, exc: SimError):
    return _error(exc.status, exc.code, exc.message)


@app.exception_handler(RequestValidationError)
async def validation_handler(_: Request, exc: RequestValidationError):
    fields = [{"field": ".".join(str(p) for p in e["loc"] if p != "body"), "message": e["msg"]} for e in exc.errors()]
    summary = "; ".join(f"{f['field']}: {f['message']}" for f in fields)
    return _error(422, "validation_error", f"Invalid request - {summary}", fields=fields)


@app.exception_handler(Exception)
async def unhandled_handler(_: Request, exc: Exception):
    log.exception("Unhandled error")
    return _error(500, "internal_error", "An unexpected error occurred. See the server log for details.")


# ------------------------------------------------------------
# Health
# ------------------------------------------------------------

@app.get("/health", tags=["Health"])
@app.get("/api/health", tags=["Health"])
def health():
    """Liveness plus database connectivity."""

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception:
        db_status = "unavailable"
    body = {"status": "ok" if db_status == "ok" else "degraded", "database": db_status, "version": app.version}
    return JSONResponse(status_code=200 if db_status == "ok" else 503, content=body)


app.include_router(legacy_router)
app.include_router(sim_router.router)

_frontend = Path(os.getenv("FRONTEND_DIR", Path(__file__).resolve().parents[2] / "frontend"))
if os.getenv("SERVE_FRONTEND", "true").lower() == "true" and (_frontend / "index.html").exists():
    app.mount("/", StaticFiles(directory=_frontend, html=True), name="frontend")
