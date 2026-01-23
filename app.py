from dotenv import load_dotenv
load_dotenv()

import csv
import os
import joblib
import pandas as pd
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import db
from db import create_db_and_tables
from schemas import (
    PredictRequest,
    PredictResponse,
    HealthResponse,
    CombinedScanResult,
    UrlHistoryResponse,
    GetUrlResultResponse,
    ApiKeyRequest,
    ApiKeyResponse,
    SuccessResponse,
)
from train_model import extract_features


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


try:
    print("Loading model and features...")
    model = joblib.load("phishing_model.joblib")
    model_features = joblib.load("model_features.joblib")
    print("Model and features loaded successfully.")
except Exception as e:
    print(f"Error loading model: {e}")
    model = None


@app.get("/home")
@app.get("/")
def main():
    print("Main API endpoint reached.")
    return {"message": "Phishy API is running."}


@app.get("/health", response_model=HealthResponse)
def health():
    if model is None:
        raise HTTPException(status_code=500, detail="Model is not loaded")

    return HealthResponse(
        status="running",
        message="ML Model API is running",
        api="ML Model",
        model_loaded=True,
    )


@app.get("/api/storage/urls", response_model=UrlHistoryResponse)
def api_get_all_urls():
    return db.get_all_urls()


@app.post("/api/storage/url-result", response_model=SuccessResponse)
def api_save_scan_result(scan_result: CombinedScanResult):
    return db.save_scan_result(scan_result)


@app.get("/api/storage/url-result/{url}", response_model=GetUrlResultResponse)
def api_get_scan_result(url: str):
    return db.get_scan_result_by_url(url)


@app.delete("/api/storage/url-result", response_model=SuccessResponse)
def api_delete_all_urls():
    return db.delete_all_urls()


@app.post("/api/storage/api-key", response_model=SuccessResponse)
def api_save_api_key(api_key: ApiKeyRequest):
    return db.save_api_key(api_key)


@app.get("/api/storage/api-key", response_model=ApiKeyResponse)
def api_get_api_key():
    return db.get_api_key()


def log_url_classification(url, status):
    Type = status.lower()
    if Type == 'phishing':
        filename = 'dataset/processed/phishing_urls.csv'
    else:
        filename = 'dataset/processed/benign_urls.csv'
    file_exists = os.path.isfile(filename)

    try:
        with open(filename, mode='a', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            if not file_exists or os.path.getsize(filename) == 0:
                writer.writerow(['url', 'Type'])
            writer.writerow([url, Type])
    except Exception as log_error:
        print(f"Failed to log URL classification: {log_error}")


@app.post("/predict", response_model=PredictResponse)
def predict(payload: PredictRequest):
    if not model:
        raise HTTPException(status_code=500, detail="Model is not loaded!")

    try:
        url_to_check = payload.url

        if not url_to_check:
            raise HTTPException(status_code=400, detail="No URL provided")

        features_dict = extract_features(url_to_check)
        features_df = pd.DataFrame([features_dict])
        features_df = features_df.reindex(columns=model_features, fill_value=0)

        prediction = model.predict(features_df)
        result = int(prediction[0])

        # model.predict_proba returns an array like this: [[0.30, 0.70]]

        probability = model.predict_proba(features_df)[0][1]
        confidence = round(float(probability) * 100, 2)

        status = "phishing" if result == 1 else "legitimate"
        log_url_classification(url_to_check, status)

        return PredictResponse(
            url=url_to_check,
            prediction=result,
            status=status,
            confidence=confidence,
        )

    except Exception as e:
        print(f"Error during prediction: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    create_db_and_tables()
    print("Starting FastAPI server...")
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
