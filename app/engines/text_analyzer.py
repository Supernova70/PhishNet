"""
ML Text Analyzer Engine — Phishing Detection via Machine Learning

Loads a pre-trained scikit-learn pipeline (TfidfVectorizer + LogisticRegression)
and predicts whether email text is phishing or legitimate.
"""

import logging
import re
from dataclasses import dataclass
from typing import Optional
from functools import lru_cache
from pathlib import Path

import joblib

from app.config import get_settings

logger = logging.getLogger(__name__)

# Phishing classification threshold — raised from 50% to 65% to reduce false positives.
# The model was trained on cleaned text; raw emails with placement drives, deadlines,
# and registration links can score 50-65% without being phishing.
PHISHING_THRESHOLD = 65.0


def _clean_text(text: str) -> str:
    """
    Preprocess email text the same way as during model training.

    Without this, the model receives raw HTML/RTF and produces unreliable predictions
    because the TF-IDF vocabulary was trained on cleaned text.
    """
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)                    # strip HTML tags
    text = re.sub(r"https?://\S+", " [URL] ", text)         # replace URLs with token
    text = re.sub(r"www\.\S+", " [URL] ", text)             # replace www URLs
    text = re.sub(r"\S+@\S+\.\S+", " [EMAIL] ", text)      # replace emails with token
    text = re.sub(r"[^a-zA-Z0-9\s\[\].,!?]", " ", text)   # remove non-alphanumeric
    text = text.lower()
    text = re.sub(r"\s+", " ", text).strip()
    return text


@dataclass
class TextAnalysisResult:
    """Result of ML text analysis."""
    is_phishing: bool
    confidence: float  # 0–100
    label: str  # "Phishing" or "Legitimate"


class TextAnalyzer:
    """Wrapper for the pre-trained phishing text classifier."""

    def __init__(self, model_path: str):
        self.model = None
        self._load_model(model_path)

    def _load_model(self, model_path: str) -> None:
        """Load the sklearn pipeline from a joblib file."""
        path = Path(model_path)
        if not path.exists():
            logger.warning(f"Model not found at {model_path}. AI scores will be 0.")
            return

        try:
            self.model = joblib.load(path)
            logger.info(f"ML model loaded from {model_path}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self.model = None

    def analyze(self, text: str) -> TextAnalysisResult:
        """
        Analyze text and return phishing probability.

        Args:
            text: Email body text (plain text or HTML)

        Returns:
            TextAnalysisResult with confidence score and label
        """
        if not self.model or not text or not text.strip():
            return TextAnalysisResult(
                is_phishing=False,
                confidence=0.0,
                label="Unknown (Model not loaded)",
            )

        try:
            # Apply same preprocessing as training — critical for accurate predictions
            cleaned = _clean_text(text)

            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba([cleaned])[0]
                phishing_prob = float(probs[1])  # Class 1 = phishing
            else:
                prediction = self.model.predict([cleaned])[0]
                phishing_prob = 1.0 if prediction == 1 else 0.0

            confidence = round(phishing_prob * 100, 2)
            is_phishing = confidence > PHISHING_THRESHOLD

            return TextAnalysisResult(
                is_phishing=is_phishing,
                confidence=confidence,
                label="Phishing" if is_phishing else "Legitimate",
            )

        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return TextAnalysisResult(
                is_phishing=False,
                confidence=0.0,
                label="Error",
            )


@lru_cache
def get_text_analyzer() -> TextAnalyzer:
    """Cached singleton — the model is loaded once and reused."""
    settings = get_settings()
    return TextAnalyzer(settings.MODEL_PATH)
