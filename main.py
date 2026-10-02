import asyncio
import logging
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from api.endpoints import router as api_router
from core.config import LOG_POLL_INTERVAL_SECONDS, LOG_WATCH_DIR, PROJECT_ROOT
from core.file_monitor import scan_log_file, scan_watch_directory
from models.database import Base, engine, migrate_legacy_schema, seed_default_roles
from sqlalchemy.exc import SQLAlchemyError


logger = logging.getLogger(__name__)


async def _watch_log_directory():
    while True:
        try:
            result = await asyncio.to_thread(scan_watch_directory, LOG_WATCH_DIR)
            if result["invalid"]:
                logger.warning("Skipped %d invalid watched log line(s)", result["invalid"])
        except (OSError, SQLAlchemyError):
            logger.exception("Background log scan failed for %s", LOG_WATCH_DIR)
        await asyncio.sleep(LOG_POLL_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(bind=engine)
    migrate_legacy_schema()
    seed_default_roles()
    LOG_WATCH_DIR.mkdir(parents=True, exist_ok=True)
    demo_log = PROJECT_ROOT / "dummy_data" / "server_access.log"
    if demo_log.is_file():
        try:
            await asyncio.to_thread(scan_log_file, demo_log)
        except (OSError, SQLAlchemyError):
            logger.exception("Initial demo log scan failed for %s", demo_log)
    watcher = asyncio.create_task(_watch_log_directory())
    try:
        yield
    finally:
        watcher.cancel()
        with suppress(asyncio.CancelledError):
            await watcher


app = FastAPI(
    title="Spor Şimdi API Güvenlik Analiz Botu",
    version="2.0.0",
    lifespan=lifespan,
)

# Backend API endpointlerimizi bağlıyoruz
app.include_router(api_router, prefix="/api/v1")

app.mount(
    "/static",
    StaticFiles(directory=str(PROJECT_ROOT / "frontend")),
    name="static",
)


@app.get("/", response_class=FileResponse)
def serve_dashboard():
    return FileResponse(PROJECT_ROOT / "frontend" / "index.html")