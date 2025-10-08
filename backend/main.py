from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import requests
import whois
import socket, ssl
import base64
from dotenv import load_dotenv
import joblib
from urllib.parse import urlparse
import re

# --- Load Environment Variables ---
load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

# --- Load the Final ML Model ---
# This happens once when the application starts up.
# We no longer need a vectorizer.
try:
    model = joblib.load('model.joblib')
    print("[*] Final ML Model loaded successfully from standard dataset.")
except FileNotFoundError:
    print("[!] Model file not found. The app will run without ML predictions.")
    model = None
# ----------------------------------------

# --- NEW Feature Extraction Function (to match the Kaggle dataset) ---
def extract_live_features(url):
    features = {}
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname if parsed_url.hostname else ''
        path = parsed_url.path if parsed_url.path else ''
    except (ValueError, TypeError):
        hostname = ''
        path = ''

    features['NumDots'] = url.count('.')
    features['SubdomainLevel'] = hostname.count('.')
    features['PathLevel'] = path.count('/')
    features['UrlLength'] = len(url)
    features['NumDash'] = url.count('-')
    
    sensitive_words = ['secure', 'login', 'signin', 'bank', 'account', 'update', 'verify', 'password']
    features['NumSensitiveWords'] = sum([url.lower().count(word) for word in sensitive_words])
    
    # These features are harder to calculate live without fetching the page content.
    # We will use sensible defaults. A more advanced version could parse the HTML.
    features['PctExtHyperlinks'] = 0.5 
    features['PctExtResourceUrls'] = 0.5
    features['InsecureForms'] = 0 # Assume forms are secure unless proven otherwise
    
    # The model expects features in this exact order
    feature_order = ['NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash', 
                     'NumSensitiveWords', 'PctExtHyperlinks', 'PctExtResourceUrls', 'InsecureForms']
    
    # Return a list of the feature values in the correct order
    return [features[f] for f in feature_order]

# --- FastAPI App Setup ---
app = FastAPI()

origins = [
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeIn(BaseModel):
    input: str

@app.post("/analyze")
async def analyze(inp: AnalyzeIn):
    url = inp.input.strip()

    if not url.startswith("http"):
        raise HTTPException(400, "Invalid URL")

    reasons = []
    score = 0
    
    # === All your previous checks (GSB, VT, WHOIS, etc.) remain the same ===
    try:
        gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        payload = { "client": {"clientId": "phishing-scanner", "clientVersion": "1.0"}, "threatInfo": { "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}], }, }
        gsb_res = requests.post(gsb_url, json=payload, timeout=5).json()
        if "matches" in gsb_res:
            score += 80
            reasons.append("Google Safe Browsing flagged this URL")
    except Exception as e:
        reasons.append(f"Google Safe Browsing check failed: {e}")

    try:
        headers = {"x-apikey": VT_API_KEY}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5)
        if vt_res.status_code == 200:
            stats = vt_res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            if malicious_count > 0:
                score += malicious_count * 10
                reasons.append(f"VirusTotal: {malicious_count} engines flagged this URL")
    except Exception as e:
        reasons.append(f"VirusTotal check failed: {e}")

    try:
        domain_info = whois.whois(url)
        if not domain_info.creation_date:
            score += 20
            reasons.append("WHOIS: No creation date found")
    except Exception as e:
        reasons.append(f"WHOIS check failed: {e}")

    try:
        hostname = url.split("//")[-1].split("/")[0]
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    score += 20
                    reasons.append("SSL: No certificate found")
    except Exception as e:
        reasons.append(f"SSL check failed: {e}")
        
    # === 6. Custom ML Model (Updated Logic) ===
    if model:
        try:
            # Extract features using the new function
            live_features = extract_live_features(url)
            
            # Make a prediction (model expects a list of lists)
            prediction = model.predict([live_features])
            phishing_prob = model.predict_proba([live_features])[0][1] # Probability of being phishing
            
            # 1 means phishing in this dataset
            if prediction[0] == 1: 
                ml_score_contribution = int(phishing_prob * 40)
                score += ml_score_contribution
                reasons.append(f"Custom ML Model detected phishing patterns (Confidence: {phishing_prob:.0%})")
        except Exception as e:
            reasons.append(f"Custom ML Model check failed: {e}")

    # --- Final Verdict Logic ---
    if score >= 80:
        verdict = "Malicious"
    elif score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return {
        "url": url,
        "verdict": verdict,
        "score": min(score, 100),
        "reasons": reasons or ["No suspicious patterns found"],
    }