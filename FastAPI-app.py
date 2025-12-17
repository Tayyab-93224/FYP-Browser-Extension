from fastapi import FastAPI, HTTPException, Request
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from train_model import extract_features
import joblib
import pandas as pd
import csv
import os
import uvicorn

# Initialize FastAPI app
app = FastAPI(title="Phishy API", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)

# Global variables for model and features
model = None
model_features = None

# Load model and features on startup
@asynccontextmanager
async def load_model():
    global model, model_features
    try:
        print("Loading model and features...")
        model = joblib.load('phishing_model.joblib')
        model_features = joblib.load('model_features.joblib')
        print("Model and features loaded successfully.")
    except Exception as e:
        print(f"Error loading model: {e}")
        model = None
        model_features = None


# Request model for prediction endpoint
class URLRequest(BaseModel):
    url: str


def log_url_classification(url: str, status: str):
    """Log URL classification to CSV file"""
    Type = status.capitalize()
    if status.lower() == 'phishing':
        filename = 'phishing_urls.csv'
    else:
        filename = 'benign_urls.csv'
    file_exists = os.path.isfile(filename)

    try:
        with open(filename, mode='a', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            if not file_exists or os.path.getsize(filename) == 0:
                writer.writerow(['url', 'Type'])
            writer.writerow([url, Type])
    except Exception as log_error:
        print(f"Failed to log URL classification: {log_error}")


@app.get('/')
@app.get('/home')
async def main():
    """Main API endpoint"""
    print("Main API endpoint reached.")
    return {"message": "Phishy API is running."}


@app.get('/health')
async def health():
    """Health check endpoint"""
    if model is None:
        raise HTTPException(
            status_code=500,
            detail={
                'status': 'error',
                'message': 'Model is not loaded',
                'api': 'ML Model'
            }
        )
    
    return {
        'status': 'running',
        'message': 'ML Model API is running',
        'api': 'ML Model',
        'model_loaded': True
    }


@app.post('/predict')
@app.get('/predict')
async def predict(request: URLRequest = None):
    """Predict if a URL is phishing or legitimate"""
    global model, model_features
    
    if not model:
        raise HTTPException(
            status_code=500,
            detail={'error': 'Model is not loaded!'}
        )

    try:
        # Handle both POST and GET requests
        if request is None:
            raise HTTPException(
                status_code=400,
                detail={'error': 'No URL provided'}
            )
        
        url_to_check = request.url

        if not url_to_check:
            raise HTTPException(
                status_code=400,
                detail={'error': 'No URL provided'}
            )

        # Extract features from URL
        features_dict = extract_features(url_to_check)
        features_df = pd.DataFrame([features_dict])
        features_df = features_df.reindex(columns=model_features, fill_value=0)

        # Make prediction
        prediction = model.predict(features_df)
        result = int(prediction[0])

        # Get probability and confidence
        probability = model.predict_proba(features_df)[0][1]
        confidence = round(float(probability) * 100, 2)

        # Determine status
        status = 'phishing' if result == 1 else 'legitimate'
        
        response = {
            'url': url_to_check,
            'prediction': result,
            'status': status,
            'confidence': confidence
        }

        # Log the classification
        log_url_classification(url_to_check, status)
        
        return response

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error during prediction: {e}")
        raise HTTPException(
            status_code=500,
            detail={'error': str(e)}
        )


if __name__ == '__main__':
    print("Starting FastAPI server...")
    uvicorn.run(app, host="0.0.0.0", port=5000, reload=True)