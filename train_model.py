"""
Phishing Guard V2 — ML Model Training Script

Trains a TF-IDF + Logistic Regression pipeline for phishing email detection.

Usage:
    pip install pandas scikit-learn matplotlib seaborn kagglehub
    python train_model.py

Output:
    data/phishing_model.joblib   — trained pipeline (TF-IDF + LogReg)
    data/training_report.txt     — metrics report
    data/learning_curve.png      — learning curve plot
    data/confusion_matrix.png    — confusion matrix plot
"""

import os
import re
import sys
import logging
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import (
    train_test_split,
    GridSearchCV,
    StratifiedKFold,
    learning_curve,
)
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    f1_score,
    roc_auc_score,
)

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).parent))
from app.engines.text_preprocess import clean_text  # noqa: E402

# ── Paths ────────────────────────────────────────────────
DATA_DIR = Path(__file__).parent / "data"
MODEL_PATH = DATA_DIR / "phishing_model.joblib"
REPORT_PATH = DATA_DIR / "training_report.txt"
LEARNING_CURVE_PATH = DATA_DIR / "learning_curve.png"
CONFUSION_MATRIX_PATH = DATA_DIR / "confusion_matrix.png"

# Curated modern samples (committed) + real-mailbox export (gitignored),
# both columns text,label with label in {0,1}. Real-world false positives
# (Reddit digest, GitLab marketing) live here so the model sees today's
# legitimate notification traffic, not just the 2016-2018 corpus.
HARD_NEGATIVES_CSV = DATA_DIR / "hard_negatives.csv"
LOCAL_HAM_CSV = DATA_DIR / "local_ham.csv"
# Hard rows are merged as plain data augmentation at weight 1.0.
# Weighting them >1 was tested and rejected: they are short snippets, so
# their tf-idf for common terms ("the", "your") is extreme — even 25x with
# C=1 pushed coef[the] to +6.6 and made generic sentences score ~95% phish.
# The real FP fix turned out to be the shared clean_text (artifacts like
# "nbsp" were the drivers), which needs no weighting to work.
HARD_SAMPLE_WEIGHT = 1.0

KAGGLE_DATASET = "naserabdullahalam/phishing-email-dataset"


# ═══════════════════════════════════════════════════════════
#  1. DATASET LOADING
# ═══════════════════════════════════════════════════════════

def find_csv_file() -> Path:
    """Find the dataset CSV file in the data directory."""

    # Check for any CSV files already extracted (including subdirectories)
    csv_files = list(DATA_DIR.glob("*.csv")) + list(DATA_DIR.glob("**/*.csv"))

    # Filter out any that are actually zip files
    valid_csvs = []
    for f in csv_files:
        with open(f, "rb") as fh:
            header = fh.read(4)
            if header != b"PK\x03\x04":  # Not a zip file
                valid_csvs.append(f)

    if valid_csvs:
        # Prefer the largest CSV (most likely the main dataset)
        best = max(valid_csvs, key=lambda f: f.stat().st_size)
        logger.info(f"Found existing CSV: {best} ({best.stat().st_size / 1e6:.1f} MB)")
        return best

    # Try extracting any zip files in data/
    import zipfile
    for f in DATA_DIR.glob("*"):
        if f.suffix in (".zip", ".csv"):  # .csv might actually be a zip
            try:
                with open(f, "rb") as fh:
                    if fh.read(4) == b"PK\x03\x04":
                        logger.info(f"Found zip archive: {f}, extracting...")
                        with zipfile.ZipFile(f) as z:
                            z.extractall(DATA_DIR)
                        # Re-check for CSVs
                        valid_csvs = [
                            c for c in DATA_DIR.glob("*.csv")
                            if open(c, "rb").read(4) != b"PK\x03\x04"
                        ]
                        if valid_csvs:
                            return max(valid_csvs, key=lambda c: c.stat().st_size)
            except Exception as e:
                logger.warning(f"Failed to extract {f}: {e}")

    # Try downloading from Kaggle using kagglehub
    logger.info("No CSV found locally. Attempting Kaggle download...")
    try:
        import kagglehub
        downloaded_path = kagglehub.dataset_download(KAGGLE_DATASET)
        logger.info(f"Downloaded to: {downloaded_path}")

        # Find CSVs in the downloaded path
        dl_path = Path(downloaded_path)
        csvs = list(dl_path.rglob("*.csv"))
        if csvs:
            # Copy the largest CSV to our data dir
            import shutil
            src = max(csvs, key=lambda c: c.stat().st_size)
            dst = DATA_DIR / src.name
            shutil.copy2(src, dst)
            logger.info(f"Copied {src.name} to data/")
            return dst
    except ImportError:
        logger.warning("kagglehub not installed. Install with: pip install kagglehub")
    except Exception as e:
        logger.warning(f"Kaggle download failed: {e}")

    print("\n" + "=" * 60)
    print("ERROR: Could not find or download the dataset.")
    print()
    print("Please download it manually:")
    print("  1. Go to: https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset")
    print("  2. Click 'Download' (you need a Kaggle account)")
    print("  3. Extract the ZIP file")
    print("  4. Place the CSV file in: data/")
    print("=" * 60)
    sys.exit(1)


def load_dataset(csv_path: Path) -> pd.DataFrame:
    """Load and validate the dataset CSV."""
    # Try different encodings
    for encoding in ["utf-8", "latin-1", "cp1252"]:
        try:
            df = pd.read_csv(csv_path, encoding=encoding, on_bad_lines="skip")
            logger.info(f"Loaded with encoding: {encoding}")
            break
        except Exception:
            continue
    else:
        raise ValueError(f"Could not read {csv_path} with any encoding")

    logger.info(f"Raw dataset: {df.shape[0]} rows, {df.shape[1]} columns")
    logger.info(f"Columns: {df.columns.tolist()}")

    # ── Detect text and label columns ────────────────────
    # Normalize column names
    df.columns = [c.strip().lower() for c in df.columns]

    text_col = None
    label_col = None

    # Common text column names
    for candidate in ["body", "email_body", "text", "content", "email_text", "email", "message"]:
        if candidate in df.columns:
            text_col = candidate
            break

    # Common label column names
    for candidate in ["label", "class", "type", "category", "is_phishing", "spam"]:
        if candidate in df.columns:
            label_col = candidate
            break

    if text_col is None or label_col is None:
        logger.info(f"Auto-detect failed. Columns: {df.columns.tolist()}")
        # Fallback: assume last column is label, longest-text column is text
        if label_col is None:
            label_col = df.columns[-1]
        if text_col is None:
            # Pick the column with longest average string length
            str_cols = df.select_dtypes(include="object").columns
            if len(str_cols) > 0:
                avg_lens = {c: df[c].astype(str).str.len().mean() for c in str_cols if c != label_col}
                text_col = max(avg_lens, key=avg_lens.get)

    logger.info(f"Using text column: '{text_col}', label column: '{label_col}'")

    # ── Standardize labels to 0/1 ────────────────────────
    df = df[[text_col, label_col]].copy()
    df.columns = ["text", "label"]
    df = df.dropna(subset=["text", "label"])

    # Map labels to binary (0 = legitimate, 1 = phishing)
    unique_labels = df["label"].unique()
    logger.info(f"Unique labels: {unique_labels}")

    if df["label"].dtype == "object":
        # Text labels — map common names
        label_map = {}
        for lbl in unique_labels:
            lbl_lower = str(lbl).lower().strip()
            if lbl_lower in ("phishing", "spam", "phish", "malicious", "1", "unsafe"):
                label_map[lbl] = 1
            elif lbl_lower in ("legitimate", "ham", "safe", "legit", "0", "benign"):
                label_map[lbl] = 0
            else:
                label_map[lbl] = 1  # Default: treat unknown as phishing for safety

        df["label"] = df["label"].map(label_map)
        logger.info(f"Label mapping: {label_map}")
    else:
        # Numeric labels — ensure 0/1
        df["label"] = df["label"].astype(int)
        if set(df["label"].unique()) - {0, 1}:
            # Multi-class: treat anything > 0 as phishing
            df["label"] = (df["label"] > 0).astype(int)

    # Convert text to string type
    df["text"] = df["text"].astype(str)

    # Remove rows with very short text (likely noise)
    df = df[df["text"].str.len() > 20]

    counts = df["label"].value_counts()
    logger.info(f"Final dataset: {len(df)} rows")
    logger.info(f"  Legitimate (0): {counts.get(0, 0)}")
    logger.info(f"  Phishing   (1): {counts.get(1, 0)}")
    logger.info(f"  Balance ratio:  {counts.get(1, 0) / len(df) * 100:.1f}% phishing")

    return df


# ═══════════════════════════════════════════════════════════
#  2. TEXT PREPROCESSING
# ═══════════════════════════════════════════════════════════
# clean_text is imported from app.engines.text_preprocess — the exact
# function runtime inference uses (single source of truth).


def load_hard_samples() -> pd.DataFrame:
    """Curated hard samples from data/hard_negatives.csv + local_ham.csv.

    Returns an empty frame when neither file exists (stock retrain).
    """
    frames = []
    for path in (HARD_NEGATIVES_CSV, LOCAL_HAM_CSV):
        if not path.exists():
            continue
        df = pd.read_csv(path)
        df = df[["text", "label"]].dropna()
        df["text"] = df["text"].astype(str)
        frames.append(df)
        logger.info(f"Loaded {len(df)} hard samples from {path.name}")
    if not frames:
        return pd.DataFrame(columns=["text", "label"])
    return pd.concat(frames, ignore_index=True)


# ═══════════════════════════════════════════════════════════
#  3. TRAINING
# ═══════════════════════════════════════════════════════════

def train_model(df: pd.DataFrame):
    """Train the TF-IDF + Logistic Regression pipeline with GridSearchCV."""

    logger.info("Cleaning text...")
    df["text_clean"] = df["text"].apply(clean_text)

    # Drop any empty rows after cleaning
    df = df[df["text_clean"].str.len() > 10]

    X = df["text_clean"]
    y = df["label"]
    if "hard" in df.columns:
        weights = np.where(df["hard"].to_numpy() == 1, HARD_SAMPLE_WEIGHT, 1.0)
    else:
        weights = np.ones(len(df))

    # ── Train/Test Split (80/20, stratified) ─────────────
    X_train, X_test, y_train, y_test, w_train, _ = train_test_split(
        X, y, weights, test_size=0.20, random_state=42, stratify=y
    )
    logger.info(f"Train: {len(X_train)}, Test: {len(X_test)}")
    logger.info(
        f"Hard-sample weight mass in train: {w_train.sum() - len(w_train):.0f}"
    )

    # ── Build Pipeline ───────────────────────────────────
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=50_000,
            ngram_range=(1, 2),     # Unigrams + bigrams
            min_df=3,               # Ignore words in < 3 docs (noise)
            max_df=0.95,            # Ignore words in > 95% of docs (stopwords)
            sublinear_tf=True,      # Apply log normalization to TF
            strip_accents="unicode",
        )),
        ("clf", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",  # Handle any class imbalance
            random_state=42,
            solver="saga",            # Good for large datasets
            n_jobs=-1,
        )),
    ])

    # ── Hyperparameter Tuning with GridSearchCV ──────────
    param_grid = {
        "clf__C": [0.01, 0.1, 1.0, 10.0],  # Regularization strength
    }

    logger.info("Running GridSearchCV (5-fold, scoring=f1)...")
    grid_search = GridSearchCV(
        pipeline,
        param_grid,
        cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=42),
        scoring="f1",
        n_jobs=2,
        verbose=1,
        return_train_score=True,
    )
    grid_search.fit(X_train, y_train, clf__sample_weight=w_train)

    # ── Results ──────────────────────────────────────────
    logger.info(f"Best C: {grid_search.best_params_['clf__C']}")
    logger.info(f"Best CV F1: {grid_search.best_score_:.4f}")

    best_model = grid_search.best_estimator_

    # ── Evaluate on Test Set ─────────────────────────────
    y_pred = best_model.predict(X_test)
    y_proba = best_model.predict_proba(X_test)[:, 1]

    accuracy = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_proba)
    cls_report = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])
    conf_matrix = confusion_matrix(y_test, y_pred)

    logger.info(f"\n{'='*50}")
    logger.info(f"TEST SET RESULTS")
    logger.info(f"{'='*50}")
    logger.info(f"Accuracy:  {accuracy:.4f}")
    logger.info(f"F1 Score:  {f1:.4f}")
    logger.info(f"ROC-AUC:   {roc_auc:.4f}")
    logger.info(f"\n{cls_report}")
    logger.info(f"Confusion Matrix:\n{conf_matrix}")

    # ── Check for Overfitting ────────────────────────────
    cv_results = grid_search.cv_results_
    best_idx = grid_search.best_index_
    train_f1 = cv_results["mean_train_score"][best_idx]
    test_f1 = cv_results["mean_test_score"][best_idx]
    gap = train_f1 - test_f1

    logger.info(f"\nOverfit Check:")
    logger.info(f"  CV Train F1: {train_f1:.4f}")
    logger.info(f"  CV Test  F1: {test_f1:.4f}")
    logger.info(f"  Gap:         {gap:.4f}")

    if gap > 0.05:
        logger.warning("⚠️ Possible overfitting detected (gap > 5%)")
    elif test_f1 < 0.80:
        logger.warning("⚠️ Possible underfitting (test F1 < 80%)")
    else:
        logger.info("✅ Model looks well-fitted!")

    # ── Save Report ──────────────────────────────────────
    report_text = (
        f"Phishing Guard V2 — ML Training Report\n"
        f"{'='*50}\n\n"
        f"Dataset: {len(df)} emails\n"
        f"Train/Test Split: 80/20 (stratified)\n"
        f"Best C (regularization): {grid_search.best_params_['clf__C']}\n"
        f"TF-IDF features: {best_model.named_steps['tfidf'].max_features}\n"
        f"N-gram range: (1, 2)\n\n"
        f"TEST SET METRICS\n"
        f"{'-'*30}\n"
        f"Accuracy:  {accuracy:.4f}\n"
        f"F1 Score:  {f1:.4f}\n"
        f"ROC-AUC:   {roc_auc:.4f}\n\n"
        f"{cls_report}\n\n"
        f"Confusion Matrix:\n{conf_matrix}\n\n"
        f"OVERFIT CHECK\n"
        f"{'-'*30}\n"
        f"CV Train F1: {train_f1:.4f}\n"
        f"CV Test  F1: {test_f1:.4f}\n"
        f"Gap:         {gap:.4f}\n"
    )

    REPORT_PATH.write_text(report_text)
    logger.info(f"Report saved to: {REPORT_PATH}")

    return best_model, X_train, y_train, X_test, y_test


# ═══════════════════════════════════════════════════════════
#  4. PLOTS
# ═══════════════════════════════════════════════════════════

def plot_learning_curve(model, X_train, y_train):
    """Generate learning curve to visualize over/underfitting."""
    try:
        import matplotlib
        matplotlib.use("Agg")  # Non-interactive backend
        import matplotlib.pyplot as plt

        logger.info("Generating learning curve...")
        train_sizes, train_scores, test_scores = learning_curve(
            model, X_train, y_train,
            cv=5,
            n_jobs=-1,
            train_sizes=np.linspace(0.1, 1.0, 10),
            scoring="f1",
        )

        train_mean = train_scores.mean(axis=1)
        train_std = train_scores.std(axis=1)
        test_mean = test_scores.mean(axis=1)
        test_std = test_scores.std(axis=1)

        fig, ax = plt.subplots(figsize=(10, 6))
        ax.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.1, color="blue")
        ax.fill_between(train_sizes, test_mean - test_std, test_mean + test_std, alpha=0.1, color="orange")
        ax.plot(train_sizes, train_mean, "o-", color="blue", label="Training F1")
        ax.plot(train_sizes, test_mean, "o-", color="orange", label="Cross-Validation F1")
        ax.set_xlabel("Training Set Size")
        ax.set_ylabel("F1 Score")
        ax.set_title("Learning Curve — Phishing Detector")
        ax.legend(loc="lower right")
        ax.grid(True, alpha=0.3)
        ax.set_ylim(0.5, 1.05)

        fig.tight_layout()
        fig.savefig(LEARNING_CURVE_PATH, dpi=150)
        plt.close(fig)
        logger.info(f"Learning curve saved to: {LEARNING_CURVE_PATH}")
    except ImportError:
        logger.warning("matplotlib not installed — skipping learning curve plot")


def plot_confusion_matrix(y_test, y_pred):
    """Generate confusion matrix heatmap."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import seaborn as sns

        cm = confusion_matrix(y_test, y_pred)
        fig, ax = plt.subplots(figsize=(8, 6))
        sns.heatmap(
            cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=["Legitimate", "Phishing"],
            yticklabels=["Legitimate", "Phishing"],
            ax=ax,
        )
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")
        ax.set_title("Confusion Matrix — Phishing Detector")
        fig.tight_layout()
        fig.savefig(CONFUSION_MATRIX_PATH, dpi=150)
        plt.close(fig)
        logger.info(f"Confusion matrix saved to: {CONFUSION_MATRIX_PATH}")
    except ImportError:
        logger.warning("matplotlib/seaborn not installed — skipping confusion matrix plot")


# ═══════════════════════════════════════════════════════════
#  5. MAIN
# ═══════════════════════════════════════════════════════════

def main():
    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║   Phishing Guard V2 — ML Model Training         ║")
    print("╚══════════════════════════════════════════════════╝")
    print()

    # 1. Find and load dataset
    csv_path = find_csv_file()
    df = load_dataset(csv_path)

    # 1b. Merge curated hard samples (modern legit traffic + modern phish)
    hard = load_hard_samples()
    if len(hard):
        df = df.assign(hard=0)
        hard = hard.assign(hard=1)
        df = pd.concat([df, hard], ignore_index=True)
        logger.info(
            f"Dataset after hard-sample merge: {len(df)} rows "
            f"({int((df['hard'] == 1).sum())} curated)"
        )

    # 2. Train model
    best_model, X_train, y_train, X_test, y_test = train_model(df)

    # 3. Generate plots
    y_pred = best_model.predict(X_test)
    plot_learning_curve(best_model, X_train, y_train)
    plot_confusion_matrix(y_test, y_pred)

    # 4. Save model
    joblib.dump(best_model, MODEL_PATH)
    logger.info(f"\n✅ Model saved to: {MODEL_PATH}")
    logger.info(f"   Model size: {MODEL_PATH.stat().st_size / 1e6:.1f} MB")

    # 5. Quick sanity check
    print("\n" + "=" * 50)
    print("SANITY CHECK — Sample Predictions")
    print("=" * 50)
    test_texts = [
        "Dear user, your account has been suspended. Click here immediately to verify your identity.",
        "Hi team, the meeting has been rescheduled to 3pm tomorrow. Please update your calendars.",
        "URGENT: Your PayPal account will be closed unless you confirm your details within 24 hours.",
        "Hey, just wanted to share the project report. Let me know if you have any questions.",
    ]
    for text in test_texts:
        cleaned = clean_text(text)
        proba = best_model.predict_proba([cleaned])[0]
        label = "🚨 PHISHING" if proba[1] > 0.5 else "✅ LEGIT"
        print(f"  {label} ({proba[1]*100:.1f}%) | {text[:70]}...")

    print(f"\n🎉 Training complete! Model ready at: {MODEL_PATH}")


if __name__ == "__main__":
    main()
