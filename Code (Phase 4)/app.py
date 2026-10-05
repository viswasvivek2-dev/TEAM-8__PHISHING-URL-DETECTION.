import os
import re
from urllib.parse import urlparse
import pandas as pd
import joblib
from flask import Flask, request, jsonify, send_from_directory

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "Frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR)

# Enable CORS for all incoming requests
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

# Locate and load the saved model artifact
MODEL_CANDIDATE_PATHS = [
    os.path.join(BASE_DIR, "phishing_url_model.joblib"),
    os.path.join(BASE_DIR, "ML", "phishing_url_model.joblib"),
    os.path.join(BASE_DIR, "..", "phishing_url_model.joblib")
]

model_path = next((p for p in MODEL_CANDIDATE_PATHS if os.path.exists(p)), None)
if model_path:
    print(f"[*] Loading model artifact from: {model_path}")
    model = joblib.load(model_path)
    print("[*] Model loaded successfully.")
else:
    model = None
    print("[!] Warning: phishing_url_model.joblib not found. Run train.py first.")

# Feature extraction matching train.py
def normalize_url(url):
    url = str(url).lower()
    url = re.sub(r"https?://", "", url)
    url = re.sub(r"^www\.", "", url)
    url = re.sub(r"[^a-z0-9./?=&_@-]", " ", url)
    url = re.sub(r"\s+", " ", url).strip()
    url = re.sub(r"/+$", "", url)  # Strip trailing slash so root domain URLs are consistent
    return url

def safe_count(text, pattern):
    try:
        return len(re.findall(pattern, str(text)))
    except Exception:
        return 0

def calculate_path_depth(clean_url):
    base_path = clean_url.split("?")[0].split("#")[0].strip("/")
    parts = base_path.split("/")
    return max(0, len(parts) - 1)

SHORTENER_REGEX = r"(?:^|[\/?.&=_-])(?:bit\.ly|goo\.gl|tinyurl|t\.co)(?:[\/?&=_-]|$)"

def extract_features(raw_url):
    clean = normalize_url(raw_url)
    
    features = {
        "clean_url": clean,
        "url_len": len(clean),
        "raw_url_len": len(str(raw_url)),
        "num_dots": safe_count(clean, r"\."),
        "num_hyphen": safe_count(clean, r"-"),
        "num_underscore": safe_count(clean, r"_"),
        "num_qmarks": safe_count(clean, r"\?"),
        "num_equal": safe_count(clean, r"="),
        "has_ip": int(bool(re.search(r"\d+\.\d+\.\d+\.\d+", clean))),
        "has_at": int("@" in str(raw_url)),
        "has_shortener": int(bool(re.search(SHORTENER_REGEX, clean))),
        "path_depth": calculate_path_depth(clean)
    }
    return pd.DataFrame([features])

# Serve Frontend
@app.route("/")
def serve_index():
    return send_from_directory(FRONTEND_DIR, "PHISHIELD.html")

@app.route("/<path:filename>")
def serve_static(filename):
    return send_from_directory(FRONTEND_DIR, filename)

# API Endpoints
@app.route("/api/health", methods=["GET", "OPTIONS"])
def health():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    return jsonify({
        "status": "online",
        "model_loaded": model is not None,
        "version": "1.0.0"
    })

@app.route("/api/scan", methods=["POST", "OPTIONS"])
def scan_url():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    if model is None:
        return jsonify({"error": "Model artifact not loaded. Train and save model first."}), 503

    payload = request.get_json(silent=True) or {}
    raw_url = payload.get("url", "").strip()

    if not raw_url:
        return jsonify({"error": "Please provide a valid 'url' in request body."}), 400

    # Extract features matching the model pipeline
    feature_df = extract_features(raw_url)

    # Perform inference
    pred = int(model.predict(feature_df)[0])
    probas = model.predict_proba(feature_df)[0]
    
    # Class 0: Legitimate, Class 1: Phishing
    legit_prob = float(probas[0])
    phish_prob = float(probas[1])

    is_phishing = (pred == 1)
    confidence = (phish_prob if is_phishing else legit_prob) * 100.0

    # Collect indicators for explainability
    indicators = []
    if feature_df["has_ip"].iloc[0] == 1:
        indicators.append("Direct IP address used instead of domain name")
    if feature_df["has_at"].iloc[0] == 1:
        indicators.append("Contains '@' symbol (HTTP auth spoofing pattern)")
    if feature_df["has_shortener"].iloc[0] == 1:
        indicators.append("Uses URL shortener (obfuscating true destination)")
    if feature_df["num_dots"].iloc[0] >= 4:
        indicators.append(f"Excessive subdomains/dots detected ({feature_df['num_dots'].iloc[0]})")
    if feature_df["path_depth"].iloc[0] >= 4:
        indicators.append(f"Deep URL path hierarchy (depth: {feature_df['path_depth'].iloc[0]})")
    if feature_df["url_len"].iloc[0] > 75:
        indicators.append(f"Abnormally long URL length ({feature_df['url_len'].iloc[0]} characters)")

    return jsonify({
        "url": raw_url,
        "clean_url": feature_df["clean_url"].iloc[0],
        "is_phishing": is_phishing,
        "label": "Phishing" if is_phishing else "Legitimate",
        "confidence": round(confidence, 2),
        "risk_score": round(phish_prob, 4),
        "threat_level": "High Risk Phishing" if is_phishing else "Safe / Legitimate",
        "indicators": indicators,
        "feature_summary": {
            "length": int(feature_df["url_len"].iloc[0]),
            "dots": int(feature_df["num_dots"].iloc[0]),
            "path_depth": int(feature_df["path_depth"].iloc[0]),
            "has_ip": bool(feature_df["has_ip"].iloc[0]),
            "has_at": bool(feature_df["has_at"].iloc[0])
        }
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n[+] PhishShield API Server running on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
