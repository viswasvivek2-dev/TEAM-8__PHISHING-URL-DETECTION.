import os
import re
from urllib.parse import urlparse
import pandas as pd

from sklearn.model_selection import GroupShuffleSplit
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
    matthews_corrcoef
)

# Load dataset
csv_filename = "PhiUSIIL_Phishing_URL_Dataset.csv"
script_dir = os.path.dirname(os.path.abspath(__file__))
potential_paths = [
    csv_filename,
    os.path.join(script_dir, csv_filename),
    os.path.join(script_dir, "..", "..", csv_filename)
]
path = next((p for p in potential_paths if os.path.exists(p)), csv_filename)

print(f"Loading dataset from: {path}")
df = pd.read_csv(path)

# Display basic info
print("Dataset shape:", df.shape)
print("\nColumns:")
print(df.columns.tolist())
print("\nFirst 5 rows:")
print(df.head())

# Normalize column names
if not df.columns.empty:
    df.columns = [str(c).strip().lower() for c in df.columns]

# Select required columns
if "url" in df.columns and "label" in df.columns:
    df = df[["url", "label"]].copy()
else:
    for url_col in ["URL", "url", "website", "site"]:
        if url_col in df.columns:
            df["url"] = df[url_col]
            break
    for label_col in ["label", "Label", "type", "class"]:
        if label_col in df.columns:
            df["label"] = df[label_col]
            break
    df = df[["url", "label"]].copy()

# Basic missing value cleanup
df = df.dropna(subset=["url", "label"]).copy()
df["url"] = df["url"].astype(str).str.strip()
df["label"] = df["label"].astype(str).str.strip().str.lower()

# Map labels to binary values (1: Phishing, 0: Legitimate)
# NOTE: In PhiUSIIL dataset, raw 0 = Phishing and raw 1 = Legitimate.
# We map so that 1 represents Phishing (positive detection target) and 0 represents Legitimate.
label_map = {
    # String descriptions
    "phishing": 1,
    "malicious": 1,
    "bad": 1,
    "yes": 1,
    "legitimate": 0,
    "safe": 0,
    "benign": 0,
    "good": 0,
    "no": 0,
    # PhiUSIIL numerical labels (0: phishing -> 1, 1: legitimate -> 0)
    "0": 1,
    "0.0": 1,
    "1": 0,
    "1.0": 0,
}

df["label"] = df["label"].map(label_map)
df = df.dropna(subset=["label"]).reset_index(drop=True)
df["label"] = df["label"].astype(int)

# Extract raw URL features BEFORE normalization/character stripping
# (Preserves features like '@' symbol and original character counts)
df["has_at"] = df["url"].str.contains("@").astype(int)
df["raw_url_len"] = df["url"].str.len()

# Extract domain for group-based train/test splitting
# (Prevents Domain Leakage: same domain appearing in both train and test sets)
def extract_domain(url):
    try:
        url_str = str(url).strip()
        if not re.match(r"^[a-zA-Z]+://", url_str):
            url_str = "http://" + url_str
        parsed = urlparse(url_str)
        domain = parsed.netloc.split(":")[0].strip().lower()
        domain = re.sub(r"^www\.", "", domain)
        return domain if domain else "unknown"
    except Exception:
        return "unknown"

df["domain"] = df["url"].apply(extract_domain)

# URL normalization
def normalize_url(url):
    url = str(url).lower()
    url = re.sub(r"https?://", "", url)
    url = re.sub(r"^www\.", "", url)
    url = re.sub(r"[^a-z0-9./?=&_@-]", " ", url)
    url = re.sub(r"\s+", " ", url).strip()
    url = re.sub(r"/+$", "", url)  # Strip trailing slash so root domains are normalized consistently
    return url

df["clean_url"] = df["url"].apply(normalize_url)

# Deduplicate AFTER normalization
# (Prevents Near-Duplicate Sample Leakage across train and test sets)
print("\nBefore deduplication:", df.shape)
df = df.drop_duplicates(subset=["clean_url"]).reset_index(drop=True)
print("After deduplication:", df.shape)

# Engineered structural features from normalized URL
def safe_count(text, pattern):
    try:
        return len(re.findall(pattern, str(text)))
    except Exception:
        return 0

def calculate_path_depth(clean_url):
    # Measures directory depth in path (excluding domain, trailing slashes, and query params)
    base_path = clean_url.split("?")[0].split("#")[0].strip("/")
    parts = base_path.split("/")
    return max(0, len(parts) - 1)

SHORTENER_REGEX = r"(?:^|[\/?.&=_-])(?:bit\.ly|goo\.gl|tinyurl|t\.co)(?:[\/?&=_-]|$)"

df["url_len"] = df["clean_url"].str.len()
df["num_dots"] = df["clean_url"].apply(lambda x: safe_count(x, r"\."))
df["num_hyphen"] = df["clean_url"].apply(lambda x: safe_count(x, r"-"))
df["num_underscore"] = df["clean_url"].apply(lambda x: safe_count(x, r"_"))
df["num_qmarks"] = df["clean_url"].apply(lambda x: safe_count(x, r"\?"))
df["num_equal"] = df["clean_url"].apply(lambda x: safe_count(x, r"="))
df["has_ip"] = df["clean_url"].str.contains(r"\d+\.\d+\.\d+\.\d+").astype(int)
df["has_shortener"] = df["clean_url"].str.contains(SHORTENER_REGEX).astype(int)
df["path_depth"] = df["clean_url"].apply(calculate_path_depth)

print("\nLabel distribution after cleaning (1 = Phishing, 0 = Legitimate):")
print(df["label"].value_counts())

# Features, target, and grouping column
feature_cols = [
    "clean_url", "url_len", "raw_url_len", "num_dots", "num_hyphen",
    "num_underscore", "num_qmarks", "num_equal", "has_ip", "has_at",
    "has_shortener", "path_depth"
]
X = df[feature_cols].copy()
y = df["label"]
groups = df["domain"]

# Domain-aware Group Train/Test Split
# Ensures no domain in X_test has any URLs in X_train, preventing TF-IDF domain memorization leakage
splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(splitter.split(X, y, groups=groups))

X_train, X_test = X.iloc[train_idx].copy(), X.iloc[test_idx].copy()
y_train, y_test = y.iloc[train_idx].copy(), y.iloc[test_idx].copy()

print(f"\nTrain set shape: {X_train.shape}, Test set shape: {X_test.shape}")
print(f"Unique domains in Train: {df['domain'].iloc[train_idx].nunique()}, in Test: {df['domain'].iloc[test_idx].nunique()}")

# Preprocessor
url_transformer = Pipeline([
    ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=5000))
])

num_transformer = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("scaler", StandardScaler())
])

numeric_features = [
    "url_len", "raw_url_len", "num_dots", "num_hyphen", "num_underscore",
    "num_qmarks", "num_equal", "has_ip", "has_at", "has_shortener",
    "path_depth"
]

preprocessor = ColumnTransformer([
    ("url_text", url_transformer, "clean_url"),
    ("numeric", num_transformer, numeric_features)
])

# Model
model = Pipeline([
    ("preprocessor", preprocessor),
    ("classifier", LogisticRegression(max_iter=1000, random_state=42))
])

# Train and evaluate
print("\nTraining model...")
model.fit(X_train, y_train)

print("\nEvaluating on test set...")
predictions = model.predict(X_test)
probas = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else None

# Confusion Matrix and Derived Parameters
cm = confusion_matrix(y_test, predictions)
tn, fp, fn, tp = cm.ravel()
total = tn + fp + fn + tp

accuracy = accuracy_score(y_test, predictions)
error_rate = (fp + fn) / total
sensitivity = tp / (tp + fn) if (tp + fn) > 0 else 0.0  # Recall / TPR
specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0  # TNR
precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0    # PPV
npv = tn / (tn + fn) if (tn + fn) > 0 else 0.0          # Negative Predictive Value
fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0          # False Positive Rate
fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0          # False Negative Rate
fdr = fp / (fp + tp) if (fp + tp) > 0 else 0.0          # False Discovery Rate
f1 = (2 * precision * sensitivity) / (precision + sensitivity) if (precision + sensitivity) > 0 else 0.0
balanced_acc = (sensitivity + specificity) / 2.0
mcc = matthews_corrcoef(y_test, predictions)
roc_auc = roc_auc_score(y_test, probas) if probas is not None else None

print("\n" + "=" * 60)
print("                 CONFUSION MATRIX")
print("=" * 60)
print(f"                       Predicted Legitimate (0)  Predicted Phishing (1)")
print(f"Actual Legitimate (0)         {tn:<12} (TN)          {fp:<12} (FP)")
print(f"Actual Phishing (1)           {fn:<12} (FN)          {tp:<12} (TP)")
print("=" * 60)

print("\n" + "=" * 60)
print("          CONFUSION MATRIX PARAMETERS & METRICS")
print("=" * 60)
print(f"Total Test Instances:               {total}")
print(f"True Positives (TP, Phishing):      {tp}")
print(f"True Negatives (TN, Legitimate):    {tn}")
print(f"False Positives (FP, Type I Error): {fp}")
print(f"False Negatives (FN, Type II Error):{fn}")
print("-" * 60)
print(f"Accuracy:                           {accuracy:.4f}  ({accuracy*100:.2f}%)")
print(f"Misclassification / Error Rate:     {error_rate:.4f}  ({error_rate*100:.2f}%)")
print(f"Sensitivity / Recall (TPR):         {sensitivity:.4f}  ({sensitivity*100:.2f}%)")
print(f"Specificity / Selectivity (TNR):    {specificity:.4f}  ({specificity*100:.2f}%)")
print(f"Precision / PPV:                    {precision:.4f}  ({precision*100:.2f}%)")
print(f"Negative Predictive Value (NPV):    {npv:.4f}  ({npv*100:.2f}%)")
print(f"False Positive Rate (FPR):          {fpr:.4f}  ({fpr*100:.2f}%)")
print(f"False Negative Rate (FNR):          {fnr:.4f}  ({fnr*100:.2f}%)")
print(f"False Discovery Rate (FDR):         {fdr:.4f}  ({fdr*100:.2f}%)")
print(f"F1-Score:                           {f1:.4f}")
print(f"Balanced Accuracy:                  {balanced_acc:.4f}  ({balanced_acc*100:.2f}%)")
print(f"Matthews Correlation Coeff (MCC):   {mcc:.4f}")
if roc_auc is not None:
    print(f"ROC-AUC Score:                      {roc_auc:.4f}")
print("=" * 60)

print("\nClassification report:")
print(classification_report(y_test, predictions, target_names=["Legitimate (0)", "Phishing (1)"]))

# Save trained model artifact
import joblib
model_filename = "phishing_url_model.joblib"
save_paths = [
    os.path.join(script_dir, model_filename),
    os.path.join(script_dir, "..", model_filename)
]
for sp in save_paths:
    joblib.dump(model, sp)
print(f"\nModel artifact saved successfully to: {save_paths[0]}")
