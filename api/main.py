"""FastAPI application for Security Suite"""
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import uvicorn

from api.routers import scope, runs, tasks, findings, reports, artifacts, health
from core.storage.database import get_db

app = FastAPI(
    title="Security Suite API - EASD & APKSlayer Integration",
    description="Domain reconnaissance via EASD and APK analysis via APKSlayer",
    version="2.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files for dashboard
dashboard_path = Path(__file__).parent.parent / "dashboard" / "v2"
if dashboard_path.exists():
    app.mount("/static", StaticFiles(directory=str(dashboard_path / "assets")), name="static")

    @app.get("/dashboard")
    async def serve_dashboard():
        """Serve the main dashboard"""
        return FileResponse(dashboard_path / "index.html")

    @app.get("/")
    async def redirect_to_dashboard():
        """Redirect root to dashboard"""
        return RedirectResponse(url="/dashboard")

# Initialize database and Telegram bot
@app.on_event("startup")
async def startup():
    """Initialize database and start Telegram bot on startup"""
    db = get_db()
    db.initialize()
    print("✅ Security Suite initialized - EASD & APKSlayer ready")

    # Start Telegram bot in background thread
    try:
        import threading

        def run_telegram_bot():
            try:
                from telegram_bot import main as bot_main
                bot_main(threaded=True)  # Run in threaded mode without signal handlers
            except Exception as e:
                print(f"⚠️  Telegram bot error: {e}")
                import traceback
                traceback.print_exc()

        bot_thread = threading.Thread(target=run_telegram_bot, daemon=True)
        bot_thread.start()
        print("✅ Telegram bot started in background")
    except Exception as e:
        print(f"⚠️  Failed to start Telegram bot: {e}")
        import traceback
        traceback.print_exc()


@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "ok",
        "database": "connected",
        "agents": ["recon", "apk_analyzer"],
        "tools": {
            "easd": "External Attack Surface Discovery",
            "apkslayer": "Android Security Analyzer"
        }
    }

# Include routers
app.include_router(health.router, prefix="/api", tags=["health"])
app.include_router(scope.router, prefix="/api", tags=["scope"])
app.include_router(runs.router, prefix="/api", tags=["runs"])
app.include_router(tasks.router, prefix="/api", tags=["tasks"])
app.include_router(findings.router, prefix="/api", tags=["findings"])
app.include_router(reports.router, prefix="/api", tags=["reports"])
app.include_router(artifacts.router, prefix="/api", tags=["artifacts"])

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
