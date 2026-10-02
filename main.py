from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from api.endpoints import router as api_router
from models.database import engine, Base
import os

# Veritabanı tablolarını oluştur
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Spor Şimdi API Güvenlik Analiz Botu",
    version="1.0.0"
)

# Backend API endpointlerimizi bağlıyoruz
app.include_router(api_router, prefix="/api/v1")

# ÖNEMLİ: Frontend klasöründeki CSS ve JS dosyalarını tarayıcıya sunmak için "mount" ediyoruz
app.mount("/static", StaticFiles(directory="frontend"), name="static")

# Frontend arayüzünü (index.html) servis ediyoruz
@app.get("/", response_class=FileResponse)
def serve_dashboard():
    html_path = os.path.join("frontend", "index.html")
    return FileResponse(html_path)