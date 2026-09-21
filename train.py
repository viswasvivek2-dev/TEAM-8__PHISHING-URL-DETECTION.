import pandas as pd
import re

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report

# Load dataset
path = "PhiUSIIL_Phishing_URL_Dataset.csv"
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

# Clean dataset
print("\nBefore cleaning:", df.shape)
df = df.drop_duplicates().reset_index(drop=True)
df = df.dropna(subset=["url", "label"]).copy()
df["url"] = df["url"].astype(str).str.strip()
df["label"] = df["label"].astype(str).str.strip().str.lower()

# Map labels to binary values
label_map = {
    "phishing": 1,
    "malicious": 1,
    "legitimate": 0,
    "safe": 0,
    "benign": 0,
    "1": 1,
    "0": 0,
    "yes": 1,
    "no": 0,
}

df["label"] = df["label"].map(label_map)
df = df.dropna(subset=["label"]).reset_index(drop=True)

# URL normalization

def normalize_url(url):
    url = str(url).lower()
    url = re.sub(r"https?://", "", url)
    url = re.sub(r"www\.", "", url)
    url = re.sub(r"[^a-z0-9./?=&_-]", " ", url)
    url = re.sub(r"\s+", " ", url).strip()
    return url


df["url"] = df["url"].apply(normalize_url)

# Engineered features

def safe_count(text, pattern):
    try:
        return len(re.findall(pattern, str(text)))
    except Exception:
        return 0


df["url_len"] = df["url"].str.len()
df["num_dots"] = df["url"].apply(lambda x: safe_count(x, r"\."))
df["num_hyphen"] = df["url"].apply(lambda x: safe_count(x, r"-"))
df["num_underscore"] = df["url"].apply(lambda x: safe_count(x, r"_"))
df["num_qmarks"] = df["url"].apply(lambda x: safe_count(x, r"\?"))
df["num_equal"] = df["url"].apply(lambda x: safe_count(x, r"="))
df["has_ip"] = df["url"].str.contains(r"\d+\.\d+\.\d+\.\d+").astype(int)
df["has_at"] = df["url"].str.contains("@").astype(int)
df["has_shortener"] = df["url"].str.contains(r"(bit\.ly|goo\.gl|tinyurl|t\.co)").astype(int)
df["path_depth"] = df["url"].str.count(r"/")

print("\nLabel distribution after cleaning:")
print(df["label"].value_counts())

# Features and target
X = df[[
    "url", "url_len", "num_dots", "num_hyphen", "num_underscore",
    "num_qmarks", "num_equal", "has_ip", "has_at", "has_shortener",
    "path_depth"
]].copy()
y = df["label"]

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Preprocessor
url_transformer = Pipeline([
    ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=5000))
])

num_transformer = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("scaler", StandardScaler())
])

preprocessor = ColumnTransformer([
    ("url_text", url_transformer, "url"),
    ("numeric", num_transformer, [
        "url_len", "num_dots", "num_hyphen", "num_underscore",
        "num_qmarks", "num_equal", "has_ip", "has_at",
        "has_shortener", "path_depth"
    ])
])

# Model
model = Pipeline([
    ("preprocessor", preprocessor),
    ("classifier", LogisticRegression(max_iter=1000, random_state=42))
])

# Train and evaluate
model.fit(X_train, y_train)
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

print("\nAccuracy:", round(accuracy, 4))
print("\nClassification report:")
print(classification_report(y_test, predictions))

# Optional: save model
# import joblib
# joblib.dump(model, "phishing_url_model.pkl")