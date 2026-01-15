"""Main FastAPI application."""
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import os
import re
from dotenv import load_dotenv

from routers import auth, events, tickets, marketplace, admin, admin_auth, wallet, ml_services_backend as ml_services, chatbot
from security_middleware import security_middleware
from middleware_metrics import MetricsMiddleware
from web_requests_middleware import WebRequestsMiddleware

from contextlib import asynccontextmanager
from web3_client import load_contracts

# Monitoring imports
from sentry_config import init_sentry
from monitoring import get_metrics

load_dotenv()

# Initialize Sentry
init_sentry()

@asynccontextmanager
async def lifespan(app: FastAPI):
    load_contracts()
    yield

# Create FastAPI app
app = FastAPI(
    title="NFT Ticketing Platform API",
    description="Backend API for NFT-based event ticketing platform",
    version="1.0.0",
    lifespan=lifespan
)

# --- CORS and Middleware Configuration ---

# Calculate CORS Origins
default_origins = [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://localhost:4201",
    "https://main.nft-ticketing-frontend.pages.dev",
    "https://nft-ticketing-frontend.pages.dev",
    "https://nft-ticketing-admin.pages.dev",
    "https://nftix-online.pages.dev",
    "https://nftix-online-admin.pages.dev",
    "https://nftix.online",
    "https://www.nftix.online",
    "https://admin.nftix.online"
]
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "").split(",")
CORS_ORIGINS = [origin.strip() for origin in CORS_ORIGINS if origin.strip()]
if not CORS_ORIGINS:
    CORS_ORIGINS = default_origins

# Middlewares are executed in reverse order of addition (LIFO for add_middleware)
# So the first one in this list to run is the LAST one added.

# 5. Add security middleware (Inner)
app.add_middleware(BaseHTTPMiddleware, dispatch=security_middleware)

# 4. Add web requests logging middleware
app.add_middleware(WebRequestsMiddleware, exclude_paths=['/health', '/metrics', '/docs', '/redoc', '/openapi.json'])

# 3. Add metrics middleware for Prometheus
app.add_middleware(MetricsMiddleware)

# 2. Add response compression (gzip)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# 1. CRITICAL: CORSMiddleware MUST be the first to run for preflight requests.
# Being last in the add_middleware sequence makes it the outermost middleware.
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_origin_regex=r"https://.*\.pages\.dev",  # Allow all Cloudflare Pages subdomains (admin, main, previews)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers with /api prefix
app.include_router(auth.router, prefix="/api")
app.include_router(events.router, prefix="/api")
app.include_router(tickets.router, prefix="/api")
app.include_router(marketplace.router, prefix="/api")
app.include_router(wallet.router, prefix="/api")  # Wallet connection routes
app.include_router(admin_auth.router, prefix="/api")  # Admin auth routes
app.include_router(admin.router, prefix="/api")  # Admin dashboard routes (protected)
app.include_router(ml_services.router, prefix="/api")  # ML services routes (fraud detection, risk analysis, recommendations, clustering, pricing)
app.include_router(chatbot.router, prefix="/api")  # Chatbot routes (Gemini API integration)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "NFT Ticketing Platform API",
        "version": "1.0.0",
        "docs": "/docs",
        "redoc": "/redoc"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(content=get_metrics(), media_type="text/plain")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
