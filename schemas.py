from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any


# ML Model API Schemas

class PredictRequest(BaseModel):
    """Request schema"""
    url: str = Field(..., description="URL to check for phishing")


class PredictResponse(BaseModel):
    """Response schema"""
    url: str
    prediction: int = Field(..., description="0 for legitimate, 1 for phishing")
    status: str = Field(..., description="'phishing' or 'legitimate'")
    confidence: float = Field(..., ge=0, le=100, description="Confidence percentage")


class HealthResponse(BaseModel):
    """Response schema for /health endpoint"""
    status: str
    message: str
    api: str = "ML Model"
    model_loaded: Optional[bool] = None


# VirusTotal Result Schemas

class VirusTotalStats(BaseModel):
    """VirusTotal scan statistics"""
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0

# This is used in the CombinedScanResult schema
class VirusTotalResult(BaseModel):
    """VirusTotal scan result structure"""
    url: str
    scanTime: str
    stats: VirusTotalStats
    isMalicious: bool
    scanSuccess: bool
    error: Optional[str] = None
