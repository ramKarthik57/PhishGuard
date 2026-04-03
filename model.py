"""
PhishGuard — ML Model Module
Lightweight logistic-regression classifier for phishing URL detection.
Ships with a self-generating synthetic training set so the model
is usable out-of-the-box without external datasets.
"""

import os
import random
import pickle
import logging
from pathlib import Path
from typing import List, Tuple, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import StandardScaler

from utils import extract_features, features_to_vector

logger = logging.getLogger("phishguard.model")

MODEL_DIR = Path(__file__).parent / "artifacts"
MODEL_PATH = MODEL_DIR / "phishguard_model.pkl"
SCALER_PATH = MODEL_DIR / "phishguard_scaler.pkl"


# ──────────────────────────────────────────────
# Synthetic Training Data Generator
# ──────────────────────────────────────────────

_LEGIT_DOMAINS = [
    "google.com", "github.com", "stackoverflow.com", "microsoft.com",
    "amazon.com", "wikipedia.org", "python.org", "nytimes.com",
    "bbc.co.uk", "linkedin.com", "apple.com", "reddit.com",
    "medium.com", "dropbox.com", "spotify.com", "netflix.com",
]

_LEGIT_PATHS = [
    "/", "/about", "/contact", "/products", "/docs", "/help",
    "/blog/2025/new-release", "/search?q=python",
]

_PHISH_TEMPLATES = [
    "http://{ip}/login/verify-account.html",
    "http://secure-bank-login.{tld}/update?id={rand}",
    "http://{sub}.{sub}.account-verify.{tld}/signin",
    "http://{ip}/paypal/confirm?token={rand}",
    "http://login-update-secure.{tld}/credential/{rand}",
    "http://{sub}.{sub}.{sub}.billing-alert.{tld}/unlock",
    "http://customer-{rand}.authenticate.{tld}/wallet",
    "http://{ip}/@admin/password-reset/{rand}",
]

_PHISH_TLDS = ["xyz", "top", "club", "click", "buzz", "icu", "gq", "ml"]

def _random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def _random_hex(length: int = 8) -> str:
    return "".join(random.choices("0123456789abcdef", k=length))

def _random_sub() -> str:
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(3, 8)))


def generate_synthetic_dataset(n_legit: int = 500, n_phish: int = 500) -> Tuple[List[List[float]], List[int]]:
    """
    Generate synthetic labelled feature vectors.
    Returns (X, y) where y=0 is legitimate, y=1 is phishing.
    """
    X: List[List[float]] = []
    y: List[int] = []

    # Legitimate samples
    for _ in range(n_legit):
        domain = random.choice(_LEGIT_DOMAINS)
        path = random.choice(_LEGIT_PATHS)
        scheme = random.choice(["https://", "https://", "https://", "http://"])  # bias HTTPS
        url = f"{scheme}{domain}{path}"
        feats = extract_features(url)
        X.append(features_to_vector(feats))
        y.append(0)

    # Phishing samples
    for _ in range(n_phish):
        template = random.choice(_PHISH_TEMPLATES)
        url = template.format(
            ip=_random_ip(),
            tld=random.choice(_PHISH_TLDS),
            sub=_random_sub(),
            rand=_random_hex(random.randint(6, 16)),
        )
        feats = extract_features(url)
        X.append(features_to_vector(feats))
        y.append(1)

    return X, y


# ──────────────────────────────────────────────
# Model Training & Persistence
# ──────────────────────────────────────────────

class PhishingClassifier:
    """Thin wrapper around a scikit-learn Random Forest pipeline."""

    def __init__(self):
        self.model: Optional[RandomForestClassifier] = None
        self.scaler: Optional[StandardScaler] = None

    # ── train ────────────────────────────────
    def train(self, n_legit: int = 800, n_phish: int = 800) -> dict:
        """
        Train on data. First checks for datasets/real_phishing.csv.
        If unavailable, falls back to generating high-quality synthetic data.
        Returns a metrics dict.
        """
        dataset_path = Path(__file__).parent / "datasets" / "real_phishing.csv"
        X_raw, y_raw = [], []

        if dataset_path.exists():
            try:
                df = pd.read_csv(dataset_path)
                if 'url' in df.columns and 'label' in df.columns:
                    logger.info("Real-world dataset found! Loading CSV data...")
                    for _, row in df.iterrows():
                        u = str(row['url'])
                        l = int(row['label'])
                        feats = extract_features(u)
                        X_raw.append(features_to_vector(feats))
                        y_raw.append(l)
                else:
                    logger.warning("Dataset CSV missing 'url' or 'label' columns. Falling back to synthetic.")
            except Exception as e:
                logger.error(f"Failed to load CSV dataset: {e}. Falling back to synthetic.")

        if not X_raw:
            logger.info("Generating synthetic training data (%d + %d samples)…", n_legit, n_phish)
            X_raw, y_raw = generate_synthetic_dataset(n_legit, n_phish)
        else:
            logger.info("Loaded %d samples from real-world dataset.", len(X_raw))

        X = np.array(X_raw, dtype=np.float64)
        y = np.array(y_raw, dtype=np.int32)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y,
        )

        self.scaler = StandardScaler()
        X_train = self.scaler.fit_transform(X_train)
        X_test = self.scaler.transform(X_test)

        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            class_weight="balanced",
            random_state=42,
        )
        self.model.fit(X_train, y_train)

        y_pred = self.model.predict(X_test)
        y_prob = self.model.predict_proba(X_test)[:, 1]
        
        acc = accuracy_score(y_test, y_pred)
        roc_auc = roc_auc_score(y_test, y_prob)
        cv_scores = cross_val_score(self.model, X, y, cv=5, scoring='accuracy')

        report = classification_report(y_test, y_pred, output_dict=True)

        logger.info(
            "Model trained | Acc: %.4f | ROC/AUC: %.4f | CV Mean: %.4f (+/-%.4f)",
            acc, roc_auc, cv_scores.mean(), cv_scores.std() * 2
        )
        return {
            "accuracy": round(acc, 4), 
            "roc_auc": round(roc_auc, 4),
            "cv_mean": round(cv_scores.mean(), 4),
            "report": report
        }

    # ── predict ──────────────────────────────
    def predict_proba(self, feature_vector: List[float]) -> float:
        """
        Return probability that the URL is phishing (class 1).
        Falls back to 0.5 if model is not loaded.
        """
        if self.model is None or self.scaler is None:
            logger.warning("Model not loaded — returning neutral probability.")
            return 0.5

        X = np.array([feature_vector], dtype=np.float64)
        X = self.scaler.transform(X)
        proba = self.model.predict_proba(X)[0]
        # proba shape: [P(legit), P(phish)]
        return float(proba[1])

    # ── save / load ──────────────────────────
    def save(self) -> None:
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(self.model, f)
        with open(SCALER_PATH, "wb") as f:
            pickle.dump(self.scaler, f)
        logger.info("Model saved → %s", MODEL_PATH)

    def load(self) -> bool:
        if MODEL_PATH.exists() and SCALER_PATH.exists():
            with open(MODEL_PATH, "rb") as f:
                self.model = pickle.load(f)
            with open(SCALER_PATH, "rb") as f:
                self.scaler = pickle.load(f)
            logger.info("Model loaded ← %s", MODEL_PATH)
            return True
        return False

    @property
    def is_ready(self) -> bool:
        return self.model is not None and self.scaler is not None


# ──────────────────────────────────────────────
# Convenience: auto-train if run directly
# ──────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
    clf = PhishingClassifier()
    metrics = clf.train()
    clf.save()
    print(f"\n[+] Training complete -- accuracy: {metrics['accuracy']}")
