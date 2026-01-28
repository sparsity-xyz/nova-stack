import logging
import uvicorn
from fastapi import FastAPI
from contextlib import asynccontextmanager
from odyn import Odyn
from chain import Chain
from tasks import EchoTask
import os
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, FileResponse, Response
from fastapi.middleware.cors import CORSMiddleware

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize components
odyn = Odyn()
chain = Chain()
echo_task = EchoTask(odyn, chain)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Echo Vault Enclave...")
    try:
        # Wait for Helios to be ready before starting background task
        # This is important in TEE where Helios starts alongside the app
        chain.wait_for_helios()
        echo_task.start()
        logger.info("Background echo task started")
    except Exception as e:
        logger.error(f"Failed to start background task: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Echo Vault Enclave...")
    echo_task.is_running = False

app = FastAPI(lifespan=lifespan)

# Add CORS middleware to support cross-origin requests from frontend dev servers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return RedirectResponse(url="/frontend/")

# Frontend static files
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "frontend")

if os.path.exists(FRONTEND_DIR):
    # Specialized catch-all for SPA routing within /frontend subpath
    @app.get("/frontend/{path:path}")
    async def serve_frontend(path: str):
        if not path or path == "":
            return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
        
        file_path = os.path.join(FRONTEND_DIR, path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
            
        # Fallback to index.html for unknown paths to support Client-Side Routing
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

    # Mount static assets if they exist (more efficient for images/js)
    # This must be mounted AFTER the catch-all to not interfere if we want custom logic, 
    # but usually mount goes first. In FastAPI, we'll just stick to the route.

@app.get("/api/status")
async def get_status():
    balance = chain.get_balance(echo_task.address)
    return {
        "address": echo_task.address,
        "balance": str(balance),
        "processed_count": echo_task.processed_count,
        "last_block": echo_task.last_block,
        "persisted_block": echo_task.persisted_block,
        "pending_count": len(echo_task.pending_hashes),
        "note": "Attestation available at /.well-known/attestation or port 18001"
    }

@app.get("/api/history")
async def get_history():
    return echo_task.history

@app.post("/.well-known/attestation")
async def get_attestation():
    try:
        att = odyn.get_attestation()
        # Return raw binary CBOR data to match production behavior
        return Response(content=att, media_type="application/octet-stream")
    except Exception as e:
        logger.error(f"Attestation failed: {e}")
        return {"error": str(e)}, 500

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
