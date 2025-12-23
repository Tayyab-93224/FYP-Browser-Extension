import pandas as pd
import tldextract
from urllib.parse import urlparse
import re
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


def extract_features(url):
    features = {}
    if not url.startswith('http'):
        url = 'http://' + url

    try:
        parsed_url = urlparse(url)
        domain_parts = tldextract.extract(url)
        domain_name = domain_parts.domain + '.' + domain_parts.suffix
        subdomain = domain_parts.subdomain
        
        features['url_length'] = len(url)
        features['hostname_length'] = len(parsed_url.netloc)
        features['path_length'] = len(parsed_url.path)
        features['count_dot'] = url.count('.')
        features['count_dash'] = url.count('-')
        features['count_underscore'] = url.count('_')
        features['count_slash'] = url.count('/')
        features['count_question'] = url.count('?')
        features['count_equals'] = url.count('=')
        features['count_at'] = url.count('@')
        features['count_ampersand'] = url.count('&')
        features['num_subdomains'] = subdomain.count('.') + 1 if subdomain else 0
        features['uses_https'] = 1 if parsed_url.scheme == 'https' else 0
        features['domain_length'] = len(domain_name)
        features['domain_has_digits'] = 1 if any(char.isdigit() for char in domain_name) else 0
        features['domain_has_non_ascii'] = 1 if any(ord(char) > 127 for char in domain_name) else 0
        
        # Checking if the domain name contains an IP address
        ip_regex = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
        features['is_ip_address'] = 1 if ip_regex.search(domain_name) else 0

    except Exception as e:
        print(f"Error parsing the URL {url}: {e}")
        feature_names = [
            'url_length', 'hostname_length', 'path_length', 'count_dot', 'count_dash', 
            'count_underscore', 'count_slash', 'count_question', 'count_equals', 
            'count_at', 'count_ampersand', 'num_subdomains', 'uses_https', 
            'is_ip_address', 'domain_length', 'domain_has_digits', 'domain_has_non_ascii'
        ]
        features = {name: 0 for name in feature_names}

    return features


print("Loading datasets...")

try:
    df_phishing = pd.read_csv('phishing_urls.csv', on_bad_lines='skip')
    df_benign = pd.read_csv('benign_urls.csv', on_bad_lines='skip')
except FileNotFoundError:
    print("Dataset files not found. Make sure the CSV files are in the same directory.")
    exit()

df_phishing['label'] = 1
df_benign['label'] = 0      # now both df's have 3 columns

print("Combining and shuffling data...")
df_combined = pd.concat([df_phishing, df_benign], ignore_index=True)
df_combined = df_combined.sample(frac=1, random_state=42).reset_index(drop=True) # .reset_index(drop=True) resets the index after shuffling

df_combined.drop_duplicates(subset=['url'], inplace=True)
df_combined.dropna(subset=['url'], inplace=True)

print(f"Total URLs in combined dataset: {len(df_combined)}")


print("Extracting features from URLs... This may take a few minutes.")
features_list = df_combined['url'].apply(extract_features) # .apply applies the function to every row

# Convert the pandas series dictionary into a plain python list
X = pd.DataFrame(features_list.tolist())
X = X.fillna(0)
y = df_combined['label']

print(f"Feature extraction completed. Shape of X: {X.shape}")


print("Splitting data into training and testing sets...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
# X_train: training features
# X_test: testing features
# y_train: training labels
# y_test: testing labels

# -------------------------------- Checkpoint --------------------------------------------------

print("Training the Random Forest model...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)

model.fit(X_train, y_train)
print("Model training completed.")


print("Evaluating model on 'unseen' test data...")
y_pred = model.predict(X_test) #X_test is the final exam of the model.

accuracy = accuracy_score(y_test, y_pred) # checking the paper of bacha, y_test are the correct answers while y_pred are the bacha's answers
print(f"\nModel Accuracy: {accuracy * 100:.2f}%")

print("\n--- Confusion Matrix ---")
print(confusion_matrix(y_test, y_pred))


print("\n--- Classification Report ---")
print(classification_report(y_test, y_pred, target_names=['Benign (0)', 'Phishing (1)']))
# target_names assigns names to the classes for better readability, without it it would just show 0 and 1


print("Saving model to 'phishing_model.joblib'...")
joblib.dump(model, 'phishing_model.joblib')

# Save the list of feature names. This is *critical* for your API
# It ensures you feed features to the model in the *exact same order*
joblib.dump(list(X.columns), 'model_features.joblib')

print("\nProcess complete! Your model is saved and ready for your backend API.")