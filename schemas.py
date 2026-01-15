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

# This one is used in the CombinedScanResult schema
class VirusTotalResult(BaseModel):
    """VirusTotal scan result structure"""
    url: str
    scanTime: str
    stats: VirusTotalStats
    isMalicious: bool
    scanSuccess: bool
    error: Optional[str] = None

# ML Model Result Schemas

# This one is used in the CombinedScanResult schema
class MLModelResult(BaseModel):
    """ML Model scan result structure"""
    url: str
    scanTime: str
    prediction: str
    confidence: float = Field(..., ge=0, le=100)
    isMalicious: bool
    scanSuccess: bool
    rawResponse: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# Combined Scan Result Schemas

class CombinedScanResult(BaseModel):
    """Combined scan result from both VirusTotal and ML Model"""
    url: str
    scanTime: str
    virusTotal: Optional[VirusTotalResult] = None
    mlModel: Optional[MLModelResult] = None
    isMalicious: bool
    scanSuccess: bool


class UrlHistoryItem(BaseModel):
    """URL history item structure (from storage.js urlList)"""
    url: str
    scanTime: str
    isMalicious: bool
    scanSuccess: bool
    hasVirusTotal: bool
    hasMlModel: bool


class UrlHistoryResponse(BaseModel):
    """Response containing list of URL history items"""
    urls: List[UrlHistoryItem]
    total: int


class GetUrlResultResponse(BaseModel):
    """Response for getting a specific URL result"""
    url: str
    scanResult: Optional[CombinedScanResult] = None
    found: bool
