from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import requests
import whois
import socket, ssl
import base64
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

app = FastAPI()

# Allow frontend origin
origins = [
    "http://localhost:3000",  # Next.js frontend
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
    verdict = "Safe"

    # === 1. Google Safe Browsing ===
    try:
        gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        payload = {
            "client": {"clientId": "phishing-scanner", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        gsb_res = requests.post(gsb_url, json=payload).json()
        if "matches" in gsb_res:
            verdict = "Malicious"
            score += 80
            reasons.append("Google Safe Browsing flagged this URL")
    except Exception as e:
        reasons.append(f"Google Safe Browsing check failed: {e}")

    # === 2. VirusTotal ===
    try:
        headers = {"x-apikey": VT_API_KEY}
        # encode URL in base64 (without "=" padding)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        if vt_res.status_code == 200:
            data = vt_res.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            if malicious_count > 0:
                verdict = "Malicious"
                score += malicious_count * 10
                reasons.append(f"VirusTotal: {malicious_count} engines flagged this URL")
    except Exception as e:
        reasons.append(f"VirusTotal check failed: {e}")

    # === 3. WHOIS Lookup ===
    try:
        domain_info = whois.whois(url)
        if not domain_info.creation_date:
            verdict = "Suspicious"
            score += 20
            reasons.append("WHOIS: No creation date found (possible fake domain)")
    except Exception as e:
        reasons.append(f"WHOIS check failed: {e}")

    # === 4. URLHaus ===
    try:
        uh_res = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url})
        uh_data = uh_res.json()
        if uh_data.get("query_status") == "ok":
            verdict = "Malicious"
            score += 70
            reasons.append("URLHaus flagged this URL")
    except Exception as e:
        reasons.append(f"URLHaus check failed: {e}")

    # === 5. SSL Certificate Check ===
    try:
        hostname = url.split("//")[-1].split("/")[0]  # extract domain
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    verdict = "Suspicious"
                    score += 20
                    reasons.append("SSL: No certificate found")
    except Exception as e:
        reasons.append(f"SSL check failed: {e}")

    # Final adjustments
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
