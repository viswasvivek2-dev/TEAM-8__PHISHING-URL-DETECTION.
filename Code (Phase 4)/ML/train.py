import os
import re
import time
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# ==========================================
# 1. CONFIGURATION & DATASET LOADING
# ==========================================

# Set SAMPLE_SIZE to an integer (e.g. 50000) for rapid testing, or None for the full dataset (235k rows)
SAMPLE_SIZE = None

csv_filename = "PhiUSIIL_Phishing_URL_Dataset.csv"
search_paths = [
    csv_filename,
    os.path.join(os.path.dirname(__file__), csv_filename),
    os.path.join(os.path.dirname(__file__), "..", "..", csv_filename),
    os.path.join("Code (Phase 4)", "ML", csv_filename)
]

dataset_path = None
for p in search_paths:
    if os.path.exists(p) and os.path.getsize(p) > 1000:
        dataset_path = p
        break

if not dataset_path:
    raise FileNotFoundError(
        f"Could not locate '{csv_filename}' with valid data. Looked in: {search_paths}"
    )

print(f"Loading dataset from: {dataset_path}")
t0 = time.time()
if SAMPLE_SIZE:
    df = pd.read_csv(dataset_path, nrows=SAMPLE_SIZE)
    print(f"Loaded sample of {len(df)} rows in {time.time() - t0:.2f}s.")
else:
    df = pd.read_csv(dataset_path)
    print(f"Loaded full dataset ({len(df)} rows, {df.shape[1]} columns) in {time.time() - t0:.2f}s.")

# Normalize column names to lowercase stripped strings
df.columns = [str(c).strip().lower() for c in df.columns]

# ==========================================
# 2. DATA CLEANING & TARGET NORMALIZATION
# ==========================================

# Drop duplicate URLs
initial_rows = len(df)
df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)
if len(df) < initial_rows:
    print(f"Removed {initial_rows - len(df)} duplicate URL entries. Remaining: {len(df)} rows.")

# Map and clean target column
if "label" not in df.columns:
    raise KeyError("Dataset does not contain a 'label' column.")

label_map = {
    "phishing": 1,
    "malicious": 1,
    "legitimate": 0,
    "safe": 0,
    "benign": 0,
    "1": 1,
    "0": 0,
    1: 1,
    0: 0,
}

df["label"] = df["label"].map(label_map).fillna(pd.to_numeric(df["label"], errors="coerce"))
df = df.dropna(subset=["label"]).reset_index(drop=True)
df["label"] = df["label"].astype(int)

# ==========================================
# 3. FEATURE ENGINEERING & EXTRACTION
# ==========================================

# Fill missing values for text and categorical columns safely
df["url"] = df["url"].fillna("").astype(str)
if "title" in df.columns:
    df["title"] = df["title"].fillna("").astype(str)
if "tld" in df.columns:
    df["tld"] = df["tld"].fillna("missing").astype(str)

# Engineer supplemental structural URL features
print("\nEngineering additional URL structural features...")
df["feat_num_dots"] = df["url"].str.count(r"\.")
df["feat_num_hyphen"] = df["url"].str.count(r"-")
df["feat_num_underscore"] = df["url"].str.count(r"_")
df["feat_path_depth"] = df["url"].str.count(r"/")
df["feat_has_at"] = df["url"].str.contains("@", regex=False).astype(int)
df["feat_has_shortener"] = df["url"].str.contains(r"(?:bit\.ly|goo\.gl|tinyurl|t\.co)", regex=True).astype(int)

# ==========================================
# 4. COLUMN CATEGORIZATION
# ==========================================

# Columns to exclude:
# - 'filename': crawler file index artifact (e.g. '521848.txt'), not a predictive feature
# - 'label': target variable
# - 'domain': fully subsumed by URL text and domain numeric properties (domainlength, isdomainip, etc.)
excluded_cols = {"filename", "label", "domain"}

# Text columns (for TF-IDF Vectorization)
text_cols = ["url"]
if "title" in df.columns:
    text_cols.append("title")

# Categorical columns (for One-Hot Encoding)
cat_cols = []
if "tld" in df.columns:
    cat_cols.append("tld")

# Numerical columns (50 dataset features + engineered features)
num_cols = [
    c for c in df.columns
    if c not in excluded_cols and c not in text_cols and c not in cat_cols
    and pd.api.types.is_numeric_dtype(df[c])
]

print(f"\nFeature Selection Summary:")
print(f"  - Text features ({len(text_cols)}): {text_cols}")
print(f"  - Categorical features ({len(cat_cols)}): {cat_cols}")
print(f"  - Numerical features ({len(num_cols)} columns):")
print(f"    {num_cols[:10]} ... (+{len(num_cols)-10} more)")
print(f"\nTarget distribution:")
print(df["label"].value_counts().rename({0: "0 (Legitimate)", 1: "1 (Phishing)"}))

# ==========================================
# 5. TRAIN / TEST SPLIT
# ==========================================

X = df[text_cols + cat_cols + num_cols]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"\nTrain set: {len(X_train)} samples | Test set: {len(X_test)} samples")

# ==========================================
# 6. PREPROCESSING PIPELINE
# ==========================================

transformers = [
    (
        "url_tfidf",
        TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=3000),
        "url",
    ),
    (
        "num_pipeline",
        Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]),
        num_cols,
    ),
]

if "title" in text_cols:
    transformers.append((
        "title_tfidf",
        TfidfVectorizer(analyzer="word", ngram_range=(1, 2), max_features=500, stop_words="english"),
        "title",
    ))

if cat_cols:
    transformers.append((
        "cat_ohe",
        OneHotEncoder(handle_unknown="ignore", min_frequency=50),
        cat_cols,
    ))

preprocessor = ColumnTransformer(transformers=transformers)

# ==========================================
# 7. MODEL DEFINITION & TRAINING
# ==========================================

model = Pipeline([
    ("preprocessor", preprocessor),
    ("classifier", LogisticRegression(max_iter=1000, random_state=42, solver="lbfgs")),
])

print("\nFitting model pipeline...")
t_train = time.time()
model.fit(X_train, y_train)
print(f"Training completed in {time.time() - t_train:.2f}s.")

# ==========================================
# 8. EVALUATION & METRICS
# ==========================================

print("\nEvaluating model on test data...")
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

print("=" * 50)
print(f"ACCURACY: {accuracy * 100:.2f}%")
print("=" * 50)

print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, predictions)
print(f"True Legitimate:  {cm[0, 0]:>6}  |  False Phishing:   {cm[0, 1]:>6}")
print(f"False Legitimate: {cm[1, 0]:>6}  |  True Phishing:    {cm[1, 1]:>6}")

print("\nClassification Report:")
print(classification_report(y_test, predictions, target_names=["Legitimate (0)", "Phishing (1)"]))

# ==========================================
# 9. OPTIONAL: MODEL SERIALIZATION
# ==========================================

# import joblib
# output_model_path = os.path.join(os.path.dirname(__file__), "phishing_url_model.pkl")
# joblib.dump(model, output_model_path)
# print(f"\nTrained model successfully saved to: {output_model_path}")