"""API routes for PhishShield AI."""

from fastapi import APIRouter, HTTPException

from app.schemas.analyze import AnalyzeRequest, AnalyzeResponse
from app.services.predictor import predictor
from app.utils.url_utils import normalize_url, validate_url

router = APIRouter(prefix="/api/v1", tags=["analysis"])


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_url(body: AnalyzeRequest):
    """Analyze a URL for phishing risk using URL-based feature extraction and ML."""

    # 1. Normalize
    url = normalize_url(body.url)

    # 2. Validate
    valid, error = validate_url(url)
    if not valid:
        raise HTTPException(status_code=400, detail=error)

    # 3. Check model availability
    if not predictor.is_ready:
        raise HTTPException(
            status_code=503,
            detail="ML model is not available. Train the model first.",
        )

    # 4. Predict
    try:
        result = predictor.predict(url)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Prediction failed.") from exc

    return result
