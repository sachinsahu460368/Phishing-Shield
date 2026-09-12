"""PhishShield AI — FastAPI application entry point."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import FRONTEND_ORIGINS
from app.api.routes import router as api_router
from app.services.predictor import predictor

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the ML model on startup (non-fatal if missing)."""
    loaded = predictor.load()
    if loaded:
        logger.info("ML model ready — %s", predictor.model_version)
    else:
        logger.warning(
            "ML model not found. /api/v1/analyze will return 503 until a model is trained."
        )
    yield


app = FastAPI(
    title="PhishShield AI API",
    description="Detect phishing URLs using ML-powered URL feature analysis.",
    version="1.0.0",
    lifespan=lifespan,
)

# ── CORS ────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ──────────────────────────────────────────────────────────────────
app.include_router(api_router)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "phishshield-ai",
        "model_loaded": predictor.is_ready,
    }
