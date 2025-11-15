import pandas as pd
import joblib
import tldextract 
from urllib.parse import urlparse
import re
from train_model import extract_features

# --- Main Testing Code ---

# 1. Load the saved model and the list of feature names
print("Loading model and feature list...")
try:
    model = joblib.load('phishing_model.joblib')
    # This feature list is CRITICAL. It ensures the order of columns
    # is the same as the data the model was trained on.
    model_features = joblib.load('model_features.joblib')
    print("Model and features loaded successfully.")
except FileNotFoundError:
    print("Error: model_phishing.joblib or model_features.joblib not found.")
    print("Please make sure you have run train_model.py first.")
    exit()

# 2. Define the "unknown" URL you want to test
# Try some obvious ones first!
# unknown_url = "https://multidisciplinary-amount-743935.framer.app/"
# unknown_url = "https://gahmg.puniro.cfd/"
# unknown_url = "https://paperclip.pk/"
unknown_url = "https://www.apponix.com/cloud-computing-training-course-in-Lahore/"


print(f"\nTesting URL: {unknown_url}")

# 3. Extract features from the new URL
# This will return a dictionary, e.g., {'url_length': 22, ...}
try:
    features_dict = extract_features(unknown_url)

    # 4. Convert the dictionary into a DataFrame in the correct column order
    # The model expects a 2D array (a DataFrame)
    
    # Create a DataFrame from the single dictionary
    features_df = pd.DataFrame([features_dict])
    
    # Re-order the columns to match the model_features list
    # This adds any missing columns (with 0) and ensures the order is identical
    features_df = features_df.reindex(columns=model_features, fill_value=0)

    print("Features extracted and formatted.")

    # 5. Make the prediction!
    prediction = model.predict(features_df)
    
    # The 'predict' method returns an array, so we get the first item
    result = prediction[0]

    # 6. Show the final result
    print("\n--- PREDICTION ---")
    if result == 1:
        print("Result: [ 1 ] - This URL is classified as PHISHING.")
    else:
        print("Result: [ 0 ] - This URL is classified as SAFE (Benign).")

except Exception as e:
    print(f"\nAn error occurred during feature extraction or prediction: {e}")
    print("This can happen with highly unusual or malformed URLs.")