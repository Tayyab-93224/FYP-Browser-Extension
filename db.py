import os
from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy import Column, JSON
from sqlmodel import SQLModel, Field, create_engine, Session, select, delete

from schemas import (CombinedScanResult,
    UrlHistoryItem,
    UrlHistoryResponse,
    GetUrlResultResponse,
    ApiKeyRequest,
    ApiKeyResponse,
    SuccessResponse)


connection_string = os.getenv("DB_URI")
print(f"Using database connection string: {connection_string}")
connection_engine = create_engine(connection_string, echo=False)


# This is a table in database that stores combined scan results of each URL
class URLScan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    url: str = Field(index=True, unique=True)
    scan_time: datetime
    is_malicious: bool = False
    scan_success: bool = True
    virus_total: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON, nullable=True))
    ml_model: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON, nullable=True))


# This is a table in database that stores the API key properties
class APIKey(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    api_key: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


def create_db_and_tables() -> None:
    SQLModel.metadata.create_all(connection_engine)


def _get_session() -> Session:
    return Session(connection_engine)


def save_scan_result(scan_result: CombinedScanResult) -> SuccessResponse:
    with _get_session() as session:
        existing: Optional[URLScan] = session.exec(
            select(URLScan).where(URLScan.url == scan_result.url)
        ).first()

        scan_time = datetime.fromisoformat(scan_result.scanTime)

        if existing:
            existing.scan_time = scan_time
            existing.is_malicious = scan_result.isMalicious
            existing.scan_success = scan_result.scanSuccess
            existing.virus_total = (scan_result.virusTotal.dict() if scan_result.virusTotal else None)
            existing.ml_model = (scan_result.mlModel.dict() if scan_result.mlModel else None)
            session.add(existing)
        else:
            row = URLScan(
                url=scan_result.url,
                scan_time=scan_time,
                is_malicious=scan_result.isMalicious,
                scan_success=scan_result.scanSuccess,
                virus_total=(scan_result.virusTotal.dict() if scan_result.virusTotal else None),
                ml_model=(scan_result.mlModel.dict() if scan_result.mlModel else None),
            )
            session.add(row)
        session.commit()
    return SuccessResponse(message="Scan result stored successfully")


def get_scan_result_by_url(url: str) -> GetUrlResultResponse:
    with _get_session() as session:
        row: Optional[URLScan] = session.exec(
            select(URLScan).where(URLScan.url == url)
        ).first()

        if not row:
            return GetUrlResultResponse(url=url, scanResult=None, found=False)

        virus_total = row.virus_total or None
        ml_model = row.ml_model or None

        combined = CombinedScanResult(
            url=row.url,
            scanTime=row.scan_time.isoformat(),
            virusTotal=virus_total,
            mlModel=ml_model,
            isMalicious=row.is_malicious,
            scanSuccess=row.scan_success,
        )

        return GetUrlResultResponse(url=url, scanResult=combined, found=True)


def get_all_urls() -> UrlHistoryResponse:
    with _get_session() as session:
        rows: List[URLScan] = session.exec(select(URLScan)).all()
        items: List[UrlHistoryItem] = []
        for row in rows:
            items.append(
                UrlHistoryItem(
                    url=row.url,
                    scanTime=row.scan_time.isoformat(),
                    isMalicious=row.is_malicious,
                    scanSuccess=row.scan_success,
                    hasVirusTotal=bool(row.virus_total),
                    hasMlModel=bool(row.ml_model),
                )
            )
    items.sort(key=lambda x: x.scanTime, reverse=True)

    return UrlHistoryResponse(urls=items, total=len(items))


def delete_all_urls() -> SuccessResponse:
    with _get_session() as session:
        session.exec(delete(URLScan))
        session.commit()
    return SuccessResponse(message="All URL scan results deleted")


def save_api_key(api_key_req: ApiKeyRequest) -> SuccessResponse:
    with _get_session() as session:
        existing: Optional[APIKey] = session.exec(select(APIKey)).first()
        
        now = datetime.utcnow()
        if existing:
            existing.api_key = api_key_req.apiKey
            existing.updated_at = now
            session.add(existing)
        else:
            row = APIKey(api_key=api_key_req.apiKey, created_at=now, updated_at=now)
            session.add(row)
        session.commit()
    return SuccessResponse(message="API key saved successfully")


def get_api_key() -> ApiKeyResponse:
    with _get_session() as session:
        api_row: Optional[APIKey] = session.exec(select(APIKey)).first()

        if not api_row:
            return ApiKeyResponse(apiKey=None, apiKeyValid=False, message="No API key configured")

        return ApiKeyResponse(apiKey=api_row.api_key, apiKeyValid=True, message="API key loaded")
