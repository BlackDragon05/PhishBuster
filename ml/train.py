"""
PhishBuster — ML Training Pipeline
===================================
Trains a Random Forest classifier on PhishTank + Tranco data.

Usage:
    python ml/train.py

Requires:
    ml/dataset/phishtank.csv   — from phishtank.com/developer_info.php
    ml/dataset/tranco_1m.csv   — from tranco-list.eu
"""

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import joblib

from phishbuster.modules.url_analyzer import analyze_url


def extract_features(url: str) -> dict:
    try:
        return analyze_url(str(url).strip())
    except Exception:
        return {}


def load_datasets(sample_size: int = 8000):
    # PhishTank — column 1 is the URL
    phish = pd.read_csv("ml/dataset/phishtank.csv", usecols=[1], header=0)
    phish.columns = ["url"]
    phish["label"] = 1

    # Tranco — column 1 is domain name
    legit = pd.read_csv("ml/dataset/tranco_1m.csv", header=None, usecols=[1])
    legit.columns = ["url"]
    legit["url"]   = "https://" + legit["url"]
    legit["label"] = 0

    n = min(sample_size, len(phish), len(legit))
    df = pd.concat([
        phish.sample(n, random_state=42),
        legit.sample(n, random_state=42)
    ]).sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"  Loaded {len(df)} URLs ({n} phishing + {n} legitimate)")
    return df


def main():
    print("\n  PhishBuster — ML Training Pipeline")
    print("  " + "─" * 40)

    print("\n[1/4] Loading datasets...")
    df = load_datasets(sample_size=8000)

    print("[2/4] Extracting features...")
    rows = []
    for i, row in df.iterrows():
        if i % 500 == 0:
            print(f"       {i}/{len(df)} URLs processed...")
        rows.append(extract_features(row["url"]))

    X = pd.DataFrame(rows)
    X = X.select_dtypes(include=["number", "bool"]).fillna(0).astype(float)
    y = df["label"].values
    print(f"       Feature matrix: {X.shape[0]} samples × {X.shape[1]} features")

    print("[3/4] Training Random Forest...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    print("[4/4] Evaluating model...\n")
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    print("  Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"    TN={cm[0,0]}  FP={cm[0,1]}")
    print(f"    FN={cm[1,0]}  TP={cm[1,1]}")

    # Top features
    importances = sorted(
        zip(X.columns, clf.feature_importances_),
        key=lambda x: x[1], reverse=True
    )[:10]
    print("\n  Top 10 features by importance:")
    for fname, imp in importances:
        bar = "█" * int(imp * 100)
        print(f"    {fname:<35} {bar} {imp:.4f}")

    # Save
    os.makedirs("ml/models", exist_ok=True)
    joblib.dump(clf,             "ml/models/phishing_model.pkl")
    joblib.dump(list(X.columns), "ml/models/feature_names.pkl")
    print("\n  ✓ Model saved to ml/models/phishing_model.pkl")
    print("  ✓ Feature names saved to ml/models/feature_names.pkl\n")


if __name__ == "__main__":
    main()
