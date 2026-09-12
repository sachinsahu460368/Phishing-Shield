"""Pydantic schemas for the /analyze endpoint."""

from pydantic import BaseModel, Field
from typing import Optional


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096, description="URL to analyze")


class AnalyzeResponse(BaseModel):
    url: str
    verdict: str                        # "safe" | "suspicious" | "phishing"
    risk_score: int                     # 0–100
    confidence: float                   # 0.0–1.0
    top_reasons: list[str]
    features: dict
    processing_time_ms: Optional[int] = None
    model_version: Optional[str] = None
    timestamp: Optional[str] = None
