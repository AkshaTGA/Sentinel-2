from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import FileResponse
from pathlib import Path
from fastapi.middleware.cors import CORSMiddleware
from .database import engine, Base
from .routers import auth, devices, telemetry, commands
from . import config

# Create tables in the database automatically
# Alembic could be used, but for simplicity and automatic self-hosting initialization,
# creating tables directly is highly reliable.
Base.metadata.create_all(bind=engine)

def database_cleanup_loop():
    import time
    import datetime
    from . import models, database
    # Let the server bind and startup fully first
    time.sleep(5)
    while True:
        try:
            db = next(database.get_db())
            try:
                limit_date = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(days=20)
                
                # Delete old telemetry
                deleted_telemetry = db.query(models.Telemetry).filter(models.Telemetry.timestamp < limit_date).delete()
                
                # Delete old commands
                deleted_commands = db.query(models.Command).filter(models.Command.created_at < limit_date).delete()
                
                db.commit()
                print(f"[INFO] Database cleanup done. Purged {deleted_telemetry} telemetry entries and {deleted_commands} commands older than 20 days.")
            finally:
                db.close()
        except Exception as e:
            print(f"[ERROR] Database cleanup failed: {e}")
        
        # Sleep for 12 hours
        time.sleep(12 * 3600)

@asynccontextmanager
async def lifespan(app: FastAPI):
    import threading
    threading.Thread(target=database_cleanup_loop, daemon=True).start()
    yield

app = FastAPI(
    title="Sentinel API",
    description="Backend API for Sentinel Linux Anti-Theft & Device Management Platform",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware configuration
# Set CORS_ORIGINS in .env (comma-separated) for production, e.g. "https://dashboard.example.com"
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)
app.include_router(devices.router)
app.include_router(telemetry.router)
app.include_router(commands.router)

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "Sentinel Backend API",
        "version": "1.0.0"
    }

from fastapi import Request

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
AGENT_DIR = ROOT_DIR / "agent"
DASHBOARD_PUBLIC_DIR = ROOT_DIR / "dashboard" / "public"

def _resolve_file(*candidates: Path) -> Path:
    for path in candidates:
        if path and path.is_file():
            return path
    return None

@app.get("/requirements.txt")
@app.get("/requirements_linux.txt")
def get_requirements_file():
    file_path = _resolve_file(
        AGENT_DIR / "requirements.txt",
        DASHBOARD_PUBLIC_DIR / "requirements.txt",
        Path.cwd() / "agent" / "requirements.txt"
    )
    if not file_path:
        raise HTTPException(status_code=404, detail="requirements.txt not found")
    return FileResponse(file_path, media_type="text/plain")

@app.get("/agent.py")
def get_agent_file():
    file_path = _resolve_file(
        AGENT_DIR / "agent.py",
        AGENT_DIR / "linux" / "agent.py",
        DASHBOARD_PUBLIC_DIR / "agent.py",
        Path.cwd() / "agent" / "agent.py"
    )
    if not file_path:
        raise HTTPException(status_code=404, detail="agent.py not found")
    return FileResponse(file_path, media_type="text/x-python")

@app.get("/install.sh")
def get_install_script(request: Request):
    file_path = _resolve_file(
        DASHBOARD_PUBLIC_DIR / "install.sh",
        ROOT_DIR / "install.sh",
        AGENT_DIR / "install.sh",
        Path.cwd() / "dashboard" / "public" / "install.sh"
    )
    if not file_path:
        raise HTTPException(status_code=404, detail="install.sh not found")
    
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    base_url = str(request.base_url).rstrip('/')
    if "127.0.0.1" not in base_url and "localhost" not in base_url:
        base_url = base_url.replace("http://", "https://")
        
    if base_url.startswith("https://"):
        ws_url = base_url.replace("https://", "wss://")
    else:
        ws_url = base_url.replace("http://", "ws://")

    content = content.replace('BACKEND_URL="https://sentinel.akshatparmar.dev"', f'BACKEND_URL="{base_url}"')
    content = content.replace('BACKEND_WS_URL="wss://sentinel.akshatparmar.dev"', f'BACKEND_WS_URL="{ws_url}"')

    return Response(content, media_type="text/x-shellscript")

@app.get("/install.ps1")
def get_install_ps1():
    file_path = _resolve_file(
        DASHBOARD_PUBLIC_DIR / "install.ps1",
        ROOT_DIR / "install.ps1"
    )
    if not file_path:
        raise HTTPException(status_code=404, detail="install.ps1 not found")
    return FileResponse(file_path, media_type="text/plain")

@app.get("/AgentWindows.py")
def get_agent_windows():
    file_path = _resolve_file(
        AGENT_DIR / "windows" / "AgentWindows.py",
        DASHBOARD_PUBLIC_DIR / "AgentWindows.py"
    )
    if not file_path:
        raise HTTPException(status_code=404, detail="AgentWindows.py not found")
    return FileResponse(file_path, media_type="text/x-python")

@app.get("/requirements_windows.txt")
def get_requirements_windows():
    file_path = _resolve_file(
        DASHBOARD_PUBLIC_DIR / "requirements_windows.txt",
        AGENT_DIR / "windows" / "requirements.txt"
    )
    if not file_path:
        raise HTTPException(status_code=404, detail="requirements_windows.txt not found")
    return FileResponse(file_path, media_type="text/plain")

@app.get("/api/agent/setup_test_device.py")
def get_setup_test_device_script(request: Request, token: str = None):
    script_path = Path(__file__).resolve().parent.parent.parent / "agent" / "setup_test_device.py"
    if not script_path.exists():
        raise HTTPException(status_code=404, detail="Setup script not found")
    
    with open(script_path, "r") as f:
        content = f.read()
        
    # Derive dynamic host URLs from the requesting client origin
    base_url = str(request.base_url).rstrip('/')
    # Force HTTPS/WSS in production (behind reverse proxy)
    if "127.0.0.1" not in base_url and "localhost" not in base_url:
        base_url = base_url.replace("http://", "https://")
        
    if base_url.startswith("https://"):
        ws_url = base_url.replace("https://", "wss://")
    else:
        ws_url = base_url.replace("http://", "ws://")
        
    content = content.replace('BACKEND_URL = "http://127.0.0.1:8000"', f'BACKEND_URL = "{base_url}"')
    content = content.replace('BACKEND_WS_URL = "ws://127.0.0.1:8000"', f'BACKEND_WS_URL = "{ws_url}"')
        
    if token:
        content = content.replace("EMBEDDED_TOKEN = None  # DYNAMIC_TOKEN_PLACEHOLDER", f'EMBEDDED_TOKEN = "{token}"')
        
    return Response(content, media_type="text/plain")

