from train_model import extract_features
import joblib
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS  # Import CORS
from urllib.parse import urlparse


# --- Initialize the Flask App ---
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# --- Load the Model and Feature List ---
# This is done ONCE when the server starts
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

# --- Define the Prediction API Endpoint ---
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
        response = {
            'url': url_to_check,
            'prediction': result,
            'status': 'phishing' if result == 1 else 'safe'
        }
        return jsonify(response)

    except Exception as e:
        print(f"Error during prediction: {e}")
        return jsonify({'error': str(e)}), 500

# --- Run the Server ---
if __name__ == '__main__':
    print("Starting Flask server...")
    # Runs the server on http://127.0.0.1:5000
    app.run(port=5000, debug=True)