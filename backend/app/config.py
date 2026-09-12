"""PhishShield AI — application configuration."""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

APP_ENV = os.getenv("APP_ENV", "development")
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))

MODEL_PATH = BASE_DIR / os.getenv("MODEL_PATH", "models/model.pkl")
METADATA_PATH = BASE_DIR / os.getenv("METADATA_PATH", "models/metadata.json")

FRONTEND_ORIGINS = [
    o.strip()
    for o in os.getenv("FRONTEND_ORIGINS", "http://localhost:5173").split(",")
    if o.strip()
]

# Verdict thresholds (risk_score 0-100)
THRESHOLD_SAFE = 40       # 0–39 → safe
THRESHOLD_SUSPICIOUS = 70  # 40–69 → suspicious, 70–100 → phishing
