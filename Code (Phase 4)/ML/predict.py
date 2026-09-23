import os
import sys
import joblib
import pandas as pd

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from feature_extractor import extract_features

_model = None

def get_model():
    global _model
    if _model is None:
        model_paths = [
            os.path.join(current_dir, "phishing_url_model.pkl"),
            os.path.join(os.getcwd(), "Code (Phase 4)", "ML", "phishing_url_model.pkl"),
            os.path.join(os.getcwd(), "phishing_url_model.pkl"),
        ]
        chosen_path = None
        for p in model_paths:
            if os.path.exists(p):
                chosen_path = p
                break
        
        if not chosen_path:
            raise FileNotFoundError(f"Trained model 'phishing_url_model.pkl' not found in: {model_paths}")
        
        _model = joblib.load(chosen_path)
    return _model

def predict_url(url: str, fetch_html: bool = False) -> dict:
    """
    Takes a URL string, extracts all model features, runs model prediction,
    and returns a comprehensive risk assessment.

    NOTE ON PHIUSIIL BENCHMARK LABELS:
      - Class 1 = Legitimate Website
      - Class 0 = Phishing Website
    """
    model = get_model()
    df_features = extract_features(url, fetch_html=fetch_html)

    raw_pred = int(model.predict(df_features)[0])
    probs = model.predict_proba(df_features)[0]

    # class 0 = Phishing, class 1 = Legitimate
    prob_phishing = float(probs[0])
    prob_legitimate = float(probs[1])

    if raw_pred == 0:
        verdict = "Phishing"
        is_phishing = 1
        confidence = prob_phishing
        risk_level = "High Risk" if confidence > 0.85 else "Suspicious"
    else:
        verdict = "Legitimate"
        is_phishing = 0
        confidence = prob_legitimate
        risk_level = "Safe" if confidence > 0.80 else "Low Risk"

    row = df_features.iloc[0]
    domain = str(row["url"]).split("://")[-1].split("/")[0] if "://" in str(row["url"]) else str(row["url"]).split("/")[0]

    feature_summary = {
        "url": str(row["url"]),
        "domain": domain,
        "tld": str(row["tld"]),
        "url_length": int(row["urllength"]),
        "is_https": bool(row["ishttps"]),
        "is_domain_ip": bool(row["isdomainip"]),
        "subdomain_count": int(row["noofsubdomain"]),
        "has_shortener": bool(row["feat_has_shortener"]),
        "has_at_symbol": bool(row["feat_has_at"]),
        "page_title": str(row["title"]) if row["title"] else ("Legitimate Domain" if is_phishing == 0 else "Suspicious / Unverified"),
        "has_password_field": bool(row["haspasswordfield"]) if not pd.isna(row["haspasswordfield"]) else False,
        "has_external_form": bool(row["hasexternalformsubmit"]) if not pd.isna(row["hasexternalformsubmit"]) else False,
    }

    return {
        "url": url,
        "prediction": verdict,
        "is_phishing": is_phishing,
        "confidence": round(confidence * 100, 2),
        "prob_legitimate": round(prob_legitimate * 100, 2),
        "prob_phishing": round(prob_phishing * 100, 2),
        "risk_level": risk_level,
        "features": feature_summary,
    }

if __name__ == "__main__":
    for test_url in [
        "https://www.google.com",
        "https://www.apple.com",
        "http://192.168.1.1/paypal-update-login-security/verify.php?user=alert",
        "http://www.f0519141.xsph.ru/account-login"
    ]:
        print(f"\n--- Testing: {test_url} ---")
        res = predict_url(test_url, fetch_html=False)
        print(f"Verdict: {res['prediction']} (Risk: {res['risk_level']}, Confidence: {res['confidence']}%)")
        print(f"Phishing Prob: {res['prob_phishing']}%, Legitimate Prob: {res['prob_legitimate']}%")
