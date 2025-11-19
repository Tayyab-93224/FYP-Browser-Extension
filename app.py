from train_model import extract_features
import joblib
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS  # Import CORS
from urllib.parse import urlparse
import csv
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

try:
    print("Loading model and features...")
    model = joblib.load('phishing_model.joblib')
    model_features = joblib.load('model_features.joblib')
    print("Model and features loaded successfully.")
except Exception as e:
    print(f"Error loading model: {e}")
    model = None

@app.route('/home', methods=['GET'])
@app.route('/', methods=['GET'])
def main():
    print("Main API endpoint reached.")
    return "Phishy API is running."

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint for the ML model API"""
    if model is None:
        return jsonify({
            'status': 'error',
            'message': 'Model is not loaded',
            'api': 'ML Model'
        }), 500
    
    return jsonify({
        'status': 'running',
        'message': 'ML Model API is running',
        'api': 'ML Model',
        'model_loaded': True
    }), 200

def log_url_classification(url: str, status: str) -> None:
    """
    Append the scanned URL and its classification outcome to the
    appropriate CSV file so results can be reviewed later.
    """
    filename = 'phishing_urls.csv' if status == 'phishing' else 'benign_urls.csv'
    file_exists = os.path.isfile(filename)

    try:
        with open(filename, mode='a', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            if not file_exists:
                writer.writerow(['timestamp', 'url', 'status'])
            writer.writerow([datetime.utcnow().isoformat(), url, status])
    except Exception as log_error:
        print(f"Failed to log URL classification: {log_error}")


@app.route('/predict', methods=['POST', 'GET'])
def predict():
    if not model:
        return jsonify({'error': 'Model is not loaded!'}), 500

    try:
        # 1. Get the URL from the JSON request body
        data = request.get_json()
        url_to_check = data.get('url')

        if not url_to_check:
            return jsonify({'error': 'No URL provided'}), 400

        # 2. Extract features from the URL
        features_dict = extract_features(url_to_check)

        # 3. Format features for the model (same as test_model.py)
        features_df = pd.DataFrame([features_dict])
        features_df = features_df.reindex(columns=model_features, fill_value=0)

        # 4. Make the prediction
        prediction = model.predict(features_df)
        result = int(prediction[0]) # Convert numpy.int64 to standard int

        # 5. Send the result back as JSON
        status = 'phishing' if result == 1 else 'safe'
        response = {
            'url': url_to_check,
            'prediction': result,
            'status': status
        }

        # 6. Log the URL to the appropriate CSV for future analysis
        log_url_classification(url_to_check, 'phishing' if result == 1 else 'benign')
        return jsonify(response)

    except Exception as e:
        print(f"Error during prediction: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting Flask server...")
    app.run(port=5000, debug=True)