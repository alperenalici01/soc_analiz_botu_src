from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from api.endpoints import router as api_router, stop_live_log_monitor
from core.config import PROJECT_ROOT
from models.database import Base, engine, migrate_legacy_schema, seed_default_roles


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    migrate_legacy_schema()
    seed_default_roles()
    try:
        yield
    finally:
        await stop_live_log_monitor()


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