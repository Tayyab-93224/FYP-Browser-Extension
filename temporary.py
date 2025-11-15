from urllib.parse import urlparse
import tldextract
import re
import pandas as pd
ip_regex = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

url = "https://msaaezuhubsnk.top/login.php?id=421"

# parsed_result = urlparse(url) # ParseResult(scheme='https', netloc='www.msaaezuhubsnk.top', path='/login.php', params='', query='id=421', fragment='')
# domain_parts = tldextract.extract(url) # ExtractResult(subdomain='www', domain='msaaezuhubsnk', suffix='top', is_private=False)

# regex = ip_regex.search("https://192.168.23.129/index.html") # True

# for char in "msaa漢ezuhubsnk.top":
#     if ord(char) > 127:
#         print(char, ord(char))


# df_phishing = pd.read_csv('phishing_links.csv', on_bad_lines='skip')
# df_benign = pd.read_csv('benign_links.csv', on_bad_lines='skip')
# print(pd.concat([df_phishing, df_benign]))

import pandas as pd
import numpy as np
import tldextract
from urllib.parse import urlparse
import re
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# --- 1. Feature Extraction ---
# This function is the "brain" of your detector.
# It converts a URL string into a vector of numbers (features).

def extract_features(url):
    features = {}
    
    # Ensure URL has a scheme for parsing
    if not url.startswith('http'):
        url = 'http://' + url

    try:
        # Parse the URL
        parsed_url = urlparse(url)
        domain_parts = tldextract.extract(url)
        domain_name = domain_parts.domain + '.' + domain_parts.suffix
        subdomain = domain_parts.subdomain
        
        # --- Feature Set ---
        
        # 1. URL Length
        features['url_length'] = len(url)
        
        # 2. Hostname Length
        features['hostname_length'] = len(parsed_url.netloc)
        
        # 3. Path Length
        features['path_length'] = len(parsed_url.path)
        
        # 4. Count of specific characters
        features['count_dot'] = url.count('.')
        features['count_dash'] = url.count('-')
        features['count_underscore'] = url.count('_')
        features['count_slash'] = url.count('/')
        features['count_question'] = url.count('?')
        features['count_equals'] = url.count('=')
        features['count_at'] = url.count('@')
        features['count_ampersand'] = url.count('&')
        
        # 5. Number of subdomains
        features['num_subdomains'] = subdomain.count('.') + 1 if subdomain else 0
        
        # 6. Protocol (HTTP vs HTTPS)
        features['uses_https'] = 1 if parsed_url.scheme == 'https' else 0
        
        # 7. Checks if the domain name contains an IP address
        ip_regex = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
        features['is_ip_address'] = 1 if ip_regex.search(domain_name) else 0

        # Will remove this in the future
        # 8. Presence of sensitive keywords in the URL
        sensitive_words = ['login', 'secure', 'account', 'verify', 'password', 'signin', 'banking', 'paypal', 'ebay']
        features['has_sensitive_words'] = 0
        for word in sensitive_words:
            if word in url.lower():
                features['has_sensitive_words'] = 1
                break
                
        # 9. Domain Length
        features['domain_length'] = len(domain_name)
        
        # 10. Checks if there is at-least one digit in a domain
        features['domain_has_digits'] = 1 if any(char.isdigit() for char in domain_name) else 0
        
        # 11. Checks for non-ASCII characters
        features['domain_has_non_ascii'] = 1 if any(ord(char) > 127 for char in domain_name) else 0

    except Exception as e:
        print(f"Error parsing the URL {url}: {e}")
        # Return a vector of zeros or NaNs if parsing fails
        # Using 0 is simpler for the model
        feature_names = [
            'url_length', 'hostname_length', 'path_length', 'count_dot', 'count_dash', 
            'count_underscore', 'count_slash', 'count_question', 'count_equals', 
            'count_at', 'count_ampersand', 'num_subdomains', 'uses_https', 
            'is_ip_address', 'has_sensitive_words', 'domain_length', 
            'domain_has_digits', 'domain_has_non_ascii'
        ]
        features = {name: 0 for name in feature_names}

    return features

# --- 2. Loading and Data Preprocessing ---

print("Loading datasets...")
# !! IMPORTANT: Update these file paths to your dataset files !!
# Assuming your files have a column named 'url'
try:
    df_phishing = pd.read_csv('phishing_links.csv', on_bad_lines='skip')
    df_benign = pd.read_csv('benign_links.csv', on_bad_lines='skip')
except FileNotFoundError:
    print("Error: Dataset files not found. Make sure the CSV files are in the same directory.")
    exit()

# Adds labels (additional columns): 1 for phishing, 0 for benign
df_phishing['label'] = 1
df_benign['label'] = 0
# now both df's have 3 columns

# Combining datasets and shuffling them
print("Combining and shuffling data...")
df_combined = pd.concat([df_phishing, df_benign], ignore_index=True)
df_combined = df_combined.sample(frac=1, random_state=42).reset_index(drop=True)

# -------------------------------- Checkpoint --------------------------------------------------

# Remove duplicates and NaNs
df_combined.drop_duplicates(subset=['url'], inplace=True)
df_combined.dropna(subset=['url'], inplace=True)

print(f"Total URLs in combined dataset: {len(df_combined)}")

# --- 3. Apply Feature Extraction ---

print("Extracting features from URLs... This may take a few minutes.")
# This applies the function to every row in the 'url' column
features_list = df_combined['url'].apply(extract_features) # .apply applies the function to every row
X = pd.DataFrame(features_list.tolist())
y = df_combined['label']

X = X.fillna(0)
# print(X)
print(f"Feature extraction complete. Shape of X: {X.shape}")

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

model = RandomForestClassifier(n_estimators=120, random_state=31)

res = model.fit(X_train, y_train)

y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\nModel Accuracy: {accuracy * 100:.2f}%")
joblib.dump(list(X.columns), 'model_features.joblib')

