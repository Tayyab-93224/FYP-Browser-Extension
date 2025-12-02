from train_model import extract_features
import joblib
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS  # Import CORS
from urllib.parse import urlparse
import csv
import os

app = Flask(__name__)
CORS(app)

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

def log_url_classification(url, status):
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


@app.route('/predict', methods=['POST', 'GET'])
def predict():
    if not model:
        return jsonify({'error': 'Model is not loaded!'}), 500

    try:
        data = request.get_json()
        url_to_check = data.get('url')

        if not url_to_check:
            return jsonify({'error': 'No URL provided'}), 400

        features_dict = extract_features(url_to_check)
        features_df = pd.DataFrame([features_dict])
        features_df = features_df.reindex(columns=model_features, fill_value=0)

        prediction = model.predict(features_df)
        result = int(prediction[0])

        # model.predict_proba returns an array like this: [[0.30, 0.70]]

        probability = model.predict_proba(features_df)[0][1]
        confidence = confidence = round(float(probability) * 100, 2)

        status = 'phishing' if result == 1 else 'legitimate'
        response = {
            'url': url_to_check,
            'prediction': result,
            'status': status,
            'confidence': confidence
        }

        log_url_classification(url_to_check, 'phishing' if result == 1 else 'legitimate')
        return jsonify(response)

    except Exception as e:
        print(f"Error during prediction: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("Starting Flask server...")
    app.run(port=5000, debug=True)