import os
import sys
from flask import Flask, request, jsonify, send_from_directory

# Configure paths to import ML layer cleanly
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BACKEND_DIR)
ML_DIR = os.path.join(PROJECT_DIR, "ML")
FRONTEND_DIR = os.path.join(PROJECT_DIR, "Frontend")

if ML_DIR not in sys.path:
    sys.path.insert(0, ML_DIR)

from predict import predict_url, get_model

# Initialize Flask app serving Frontend directory
app = Flask(__name__, static_folder=FRONTEND_DIR)

# Enable CORS for all routes (allows frontend to call API whether served via HTTP or local file)
@app.after_request
def apply_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

# Serve Frontend HTML
@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "PHISHIELD.html")

# Serve Frontend static assets (CSS, JS, images, etc.)
@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)

# Health check endpoint
@app.route("/api/health", methods=["GET"])
def health():
    try:
        model = get_model()
        model_ready = model is not None
    except Exception as e:
        model_ready = False
    
    return jsonify({
        "status": "online" if model_ready else "degraded",
        "service": "PhishShield ML Detection Engine",
        "model_loaded": model_ready,
        "api_version": "1.0.0"
    })

# URL scanning endpoint
@app.route("/api/scan", methods=["POST", "OPTIONS"])
def scan_url():
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({
            "error": "URL parameter is required."
        }), 400

    # Optional parameter: whether to attempt fast HTML scrape for rich page features
    fetch_html = bool(data.get("fetch_html", True))

    try:
        result = predict_url(url, fetch_html=fetch_html)
        return jsonify({
            "success": True,
            **result
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to analyze URL: {str(e)}"
        }), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"==================================================")
    print(f"PhishShield Backend Server starting on port {port}")
    print(f"Serving Frontend from: {FRONTEND_DIR}")
    print(f"ML Module loaded from: {ML_DIR}")
    print(f"Access Web UI at: http://127.0.0.1:{port}")
    print(f"==================================================")
    # Preload model at startup
    try:
        get_model()
        print("Model preloaded successfully into memory.")
    except Exception as e:
        print(f"Warning: Model could not be preloaded: {e}")
    
    app.run(host="0.0.0.0", port=port, debug=False)
