import sys
import json
import re
import requests
import joblib  # New import for loading the model
from urllib.parse import urlparse  # New import for feature extraction

# --- Load the saved model and vectorizer ---
# This happens once when the script starts
try:
    model = joblib.load('model.joblib')
    vectorizer = joblib.load('vectorizer.joblib')
    print("[*] ML Model and vectorizer loaded successfully.")
except FileNotFoundError:
    print("[!] Model files not found. The script will run without ML predictions.")
    model = None
    vectorizer = None
# -------------------------------------------

# --- Feature Extraction Function ---
# This must be the EXACT same function used in train_model.py
def extract_lexical_features(url):
    """Extracts lexical features from a URL into a dictionary."""
    features = {}
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname if parsed_url.hostname else ''
    except (ValueError, TypeError):
        hostname = ''
        
    features['url_length'] = len(url)
    features['hostname_length'] = len(hostname)
    features['dot_count'] = url.count('.')
    features['hyphen_count'] = url.count('-')
    features['slash_count'] = url.count('/')
    features['has_ip_address'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname) else 0
    
    suspicious_keywords = ['secure', 'login', 'signin', 'bank', 'account', 'update', 'verify', 'webscr', 'password']
    for keyword in suspicious_keywords:
        features[f'has_{keyword}_keyword'] = 1 if keyword in url.lower() else 0
    return features
# -----------------------------------

def analyze_message(message_text):
    """
    Finds a URL, (tries to) expand it, and scores it with the ML model.
    """
    url_pattern = r'https?://[^\s/$.?#].[^\s]*'
    match = re.search(url_pattern, message_text)

    if not match:
        return {"error": "No URL found in the message."}

    original_url = match.group(0)
    
    # NOTE: As we discovered, live expansion is difficult.
    # For now, the model will analyze the URL it can find.
    # We will assume final_url is the same as original_url for now.
    final_url = original_url

    # --- NEW: Use the ML Model to get a risk score ---
    ml_score = -1.0  # Default score if model isn't loaded
    if model and vectorizer:
        # 1. Extract features from the new URL
        url_features = extract_lexical_features(final_url)
        
        # 2. Transform features using the loaded vectorizer
        transformed_features = vectorizer.transform([url_features])
        
        # 3. Predict the probability of being a phishing URL
        # predict_proba gives [[prob_benign, prob_phishing]]
        prediction_probability = model.predict_proba(transformed_features)
        
        # Get the probability for the "phishing" class (which is label 1)
        ml_score = prediction_probability[0][1]
    # ------------------------------------------------

    analysis_result = {
        "original_url": original_url,
        "final_url": final_url,
        "status": "SUCCESS",
        "ml_phishing_score": f"{ml_score:.2f}"  # Format score to 2 decimal places
    }
    return analysis_result

if __name__ == "__main__":
    if len(sys.argv) > 1:
        message_from_command_line = sys.argv[1]
        result = analyze_message(message_from_command_line)
        print(json.dumps(result))
    else:
        # For direct testing of this script
        test_message = "please login to your bank account here http://123-update-account.com/login"
        print("--- Running test analysis ---")
        print(json.dumps(analyze_message(test_message), indent=2))