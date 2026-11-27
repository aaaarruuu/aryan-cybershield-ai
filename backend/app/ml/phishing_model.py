"""Phishing text classifier (TF-IDF + Logistic Regression) with reproducible, honest evaluation.

IMPORTANT: the bundled training corpus is SYNTHETIC (template-generated, see scripts/generate_sample_data.py).
Scores on a held-out split of that corpus are near-perfect because train and test share templates, so they say
nothing about real-world performance. A separate small HAND-WRITTEN set (n=16) is reported as a more realistic,
but still tiny, check. To train on a real dataset, pass a CSV with `text,label` columns (labels: phishing/legitimate).
"""
import json
import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

ART_DIR = Path(__file__).parent / "artifacts"
MODEL_PATH = ART_DIR / "phishing_model.joblib"
REPORT_PATH = ART_DIR / "phishing_evaluation.json"
ROOT = Path(__file__).resolve().parents[3]
SYNTH_CSV = ROOT / "sample_data" / "datasets" / "phishing_synthetic.csv"
HAND_JSON = ROOT / "sample_data" / "datasets" / "phishing_eval_handwritten.json"
SEED = 42


def _metrics(y_true, y_pred) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {"n": int(len(y_true)), "accuracy": round(accuracy_score(y_true, y_pred), 4),
            "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
            "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
            "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
            "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}


def _pipeline() -> Pipeline:
    return Pipeline([("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=2, sublinear_tf=True)),
                     ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=SEED))])


def train(csv_path: str | None = None, save: bool = True) -> dict:
    path = Path(csv_path) if csv_path else SYNTH_CSV
    df = pd.read_csv(path).dropna(subset=["text", "label"])
    df = df[df["label"].isin(["phishing", "legitimate"])].drop_duplicates(subset="text")  # dedupe to limit leakage
    y = (df["label"] == "phishing").astype(int)
    X_tr, X_te, y_tr, y_te = train_test_split(df["text"], y, test_size=0.25, stratify=y, random_state=SEED)
    pipe = _pipeline().fit(X_tr, y_tr)
    report = {"dataset": str(path.name), "dataset_is_synthetic": csv_path is None, "split": "75/25 stratified, seed 42",
              "train_rows": int(len(X_tr)), "heldout_split": _metrics(y_te, pipe.predict(X_te)),
              "note": "Held-out split of a synthetic template corpus: scores are optimistic and NOT evidence of real-world accuracy."}
    if HAND_JSON.exists():
        hand = json.loads(HAND_JSON.read_text())
        hy = np.array([1 if r["label"] == "phishing" else 0 for r in hand])
        hp = pipe.predict([r["text"] for r in hand])
        report["handwritten_eval"] = _metrics(hy, hp)
        report["handwritten_eval"]["note"] = "16 hand-written emails never used for training; very small sample, wide uncertainty."
        report["handwritten_eval"]["misclassified"] = [hand[i]["text"][:80] for i in np.where(hp != hy)[0]]
    pipe.fit(df["text"], y)  # final model uses all data; metrics above come from the split models
    if save:
        ART_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(pipe, MODEL_PATH)
        REPORT_PATH.write_text(json.dumps(report, indent=2))
    return report


_model = None


def load_model() -> Pipeline:
    """Load the serialised model, training it on first use if missing (takes ~1s on the bundled corpus)."""
    global _model
    if _model is None:
        if not MODEL_PATH.exists():
            train()
        _model = joblib.load(MODEL_PATH)
    return _model


def predict(text: str) -> dict:
    p = float(load_model().predict_proba([text])[0][1])
    return {"label": "phishing" if p >= 0.5 else "legitimate", "phishing_probability": round(p, 4)}


def evaluation_report() -> dict:
    if not REPORT_PATH.exists():
        train()
    return json.loads(REPORT_PATH.read_text())


if __name__ == "__main__":
    print(json.dumps(train(os.environ.get("PHISHING_CSV")), indent=2))
