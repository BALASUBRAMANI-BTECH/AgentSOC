from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.api.endpoints import router
from app.services.websocket_manager import ws_manager
from app.database.mongodb import db_repo

frontend_dist = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"


import logging
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Connect to MongoDB and setup indexes
    await db_repo.connect()

    # Seed baseline incidents if database is fresh/empty
    try:
        existing_incs = await db_repo.get_incidents(limit=5)
        if not existing_incs:
            from app.api.endpoints import receive_event
            from app.services.simulation_service import simulation_service
            import json
            sample_file = Path(__file__).resolve().parent.parent.parent / "sample_events.json"
            if sample_file.exists():
                with open(sample_file, "r") as f:
                    raw_events = json.load(f)
                from app.models.event import SecurityEvent
                for raw_ev in raw_events:
                    await receive_event(SecurityEvent(**raw_ev))
            # Also inject data exfiltration scenario so all 3 correlated incidents exist
            exfil_events = simulation_service.generate_events("data_exfiltration", count_override=6)
            for ev in exfil_events:
                await receive_event(ev)
            logger.info("Successfully seeded baseline security incidents.")
    except Exception as e:
        logger.warning(f"Initial telemetry seeding skipped: {e}")

    yield
    # Shutdown logic if needed


app = FastAPI(
    title="AgentSOC",
    description="Autonomous AI-Powered Security Operations Center for Real-Time Threat Detection, Investigation & Response",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for React dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routes
app.include_router(router)

# Mount frontend static assets if built
if frontend_dist.exists() and (frontend_dist / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(frontend_dist / "assets")), name="assets")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time WebSocket endpoint for live SOC dashboard streaming."""
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "AgentSOC Backend",
        "mongodb_connected": db_repo.is_connected
    }


@app.get("/dashboard")
def dashboard():
    """Serves the AgentSOC React Dashboard."""
    index_file = frontend_dist / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "Frontend build not found. Run 'npm run build' in frontend/"}


@app.get("/investigate/{incident_id}")
@app.get("/incident/{incident_id}")
def incident_spa_page(incident_id: str, request: Request):
    """Serves React Dashboard for client-side incident investigation routes."""
    index_file = frontend_dist / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "Frontend build not found. Run 'npm run build' in frontend/"}


@app.get("/")
def home(request: Request):
    accept = request.headers.get("accept", "")
    index_file = frontend_dist / "index.html"
    if index_file.exists():
        if "application/json" in accept and "text/html" not in accept:
            return {
                "project": "AgentSOC",
                "status": "running",
                "dashboard": "/dashboard",
                "docs": "/docs",
                "websocket": "/ws"
            }
        return FileResponse(index_file)
    return {
        "project": "AgentSOC",
        "status": "running",
        "dashboard": "/dashboard",
        "docs": "/docs",
        "websocket": "/ws"
    }

