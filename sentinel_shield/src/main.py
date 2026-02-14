"""
Sentinel Shield - Main Application Entry Point
FastAPI-based Enterprise Security Platform
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from contextlib import asynccontextmanager
import uvicorn
from datetime import datetime

# Import routers
from api import auth, emails, links, threats, dashboard
from api import viewer, blocklist
from api import darkweb, training, mobile, ai_analyst, plugins, browser_ext
from api import resources, dns_security, honeypot
from api import sandbox
from api import cve_monitor, dlp, session_protection

# Application metadata
APP_NAME = "Sentinel Shield"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = """
🛡️ **Sentinel Shield** - Enterprise Security Platform

## Features
- 🎣 Phishing Detection with ML
- 🔗 Link Security Analysis
- 🦠 Malware Sandbox
- ⚡ Automated Threat Response
- 📊 Security Dashboard

## Quick Start
- POST `/api/v1/emails/analyze` - Analyze email for threats
- POST `/api/v1/links/analyze` - Check URL safety
- GET `/api/v1/dashboard/stats` - View statistics
"""

# Startup and shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management"""
    # Startup
    print("=" * 60)
    print(f"🛡️  {APP_NAME} v{APP_VERSION}")
    print("=" * 60)
    print(f"🚀 Starting server...")
    print(f"📊 Loading ML models...")
    
    # Initialize services
    from services.ml_service import MLService
    app.state.ml_service = MLService()
    
    print(f"✅ Server ready at http://localhost:8000")
    print(f"📄 API docs at http://localhost:8000/docs")
    print("=" * 60)
    
    yield
    
    # Shutdown
    print("\n🛑 Shutting down Sentinel Shield...")

# Create FastAPI app
app = FastAPI(
    title=APP_NAME,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(emails.router, prefix="/api/v1/emails", tags=["Email Analysis"])
app.include_router(links.router, prefix="/api/v1/links", tags=["Link Analysis"])
app.include_router(threats.router, prefix="/api/v1/threats", tags=["Threat Intelligence"])
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["Dashboard"])
app.include_router(viewer.router, prefix="/api/v1/viewer", tags=["Safe Email Viewer"])
app.include_router(blocklist.router, prefix="/api/v1/blocklist", tags=["Blocklist Management"])
app.include_router(darkweb.router, prefix="/api/v1/darkweb", tags=["Dark Web Monitoring"])
app.include_router(training.router, prefix="/api/v1/training", tags=["Gamified Training"])
app.include_router(mobile.router, prefix="/api/v1/mobile", tags=["Mobile App Shield"])
app.include_router(ai_analyst.router, prefix="/api/v1/ai", tags=["AI Security Analyst"])
app.include_router(plugins.router, prefix="/api/v1/plugins", tags=["Plugin Marketplace"])
app.include_router(browser_ext.router, prefix="/api/v1/extension", tags=["Browser Extension"])
app.include_router(resources.router, prefix="/api/v1/resources", tags=["Resources & Integrations"])
app.include_router(dns_security.router, prefix="/api/v1/dns", tags=["DNS & Certificate Security"])
app.include_router(honeypot.router, prefix="/api/v1/honeypot", tags=["Honeypot Auto-Responder"])
app.include_router(sandbox.router, prefix="/api/v1/sandbox", tags=["Document Sandbox"])
app.include_router(cve_monitor.router, prefix="/api/v1/cve", tags=["CVE & Vulnerability Monitor"])
app.include_router(dlp.router, prefix="/api/v1/dlp", tags=["Data Loss Prevention"])
app.include_router(session_protection.router, prefix="/api/v1/sessions", tags=["Session & Cookie Protection"])

# Mount static files
import os
static_path = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve landing page"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Sentinel Shield</title>
        <style>
            body {
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #1a365d 0%, #2c5282 100%);
                color: white;
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                margin: 0;
            }
            .container {
                text-align: center;
                padding: 40px;
            }
            h1 { font-size: 48px; margin-bottom: 10px; }
            p { font-size: 20px; opacity: 0.9; }
            .links {
                margin-top: 40px;
            }
            a {
                display: inline-block;
                background: white;
                color: #2c5282;
                padding: 15px 30px;
                border-radius: 8px;
                text-decoration: none;
                margin: 10px;
                font-weight: 600;
            }
            a:hover { transform: scale(1.05); }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Sentinel Shield</h1>
            <p>Enterprise Security Platform</p>
            <div class="links">
                <a href="/docs">📄 API Documentation</a>
                <a href="/api/v1/dashboard/stats">📊 Dashboard</a>
            </div>
        </div>
    </body>
    </html>
    """


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": APP_NAME,
        "version": APP_VERSION,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/viewer", response_class=HTMLResponse)
async def viewer_demo():
    """Serve the safe email viewer demo page"""
    import os
    static_path = os.path.join(os.path.dirname(__file__), "static", "viewer_demo.html")
    if os.path.exists(static_path):
        with open(static_path, 'r', encoding='utf-8') as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Viewer demo not found</h1>", status_code=404)


@app.get("/dashboard", response_class=HTMLResponse)
async def admin_dashboard():
    """Serve the admin dashboard"""
    import os
    static_path = os.path.join(os.path.dirname(__file__), "static", "dashboard.html")
    if os.path.exists(static_path):
        with open(static_path, 'r', encoding='utf-8') as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Dashboard not found</h1>", status_code=404)


@app.get("/inbox", response_class=HTMLResponse)
async def client_inbox():
    """Serve the client email inbox (user view)"""
    import os
    static_path = os.path.join(os.path.dirname(__file__), "static", "client_inbox.html")
    if os.path.exists(static_path):
        with open(static_path, 'r', encoding='utf-8') as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Client inbox not found</h1>", status_code=404)


@app.get("/architecture", response_class=HTMLResponse)
async def technical_resume():
    """Serve the technical architecture resume"""
    import os
    file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "Sentinel_Shield_Technical_Resume.html")
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Architecture document not found</h1>", status_code=404)


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
