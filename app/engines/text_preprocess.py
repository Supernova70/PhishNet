"""Shared text preprocessing for the phishing classifier.

Single source of truth: training (train_model.py) and runtime inference
(app/engines/text_analyzer.py) must see identical text, otherwise the
TF-IDF vocabulary drifts between what the model learned and what it is
fed at prediction time.
"""

import html
import re


def clean_text(text: str) -> str:
    """Normalize raw email text (plain or HTML) for the ML pipeline.

    - Drops <script>/<style> blocks whole: their CSS/JS tokens (width,
      font, margin, nbsp) survive tag stripping and read as phish
      signals to the model — the source of a real-world false positive
      on a Reddit HTML digest.
    - Strips remaining HTML tags and decodes entities (&nbsp; etc).
    - Replaces URLs with [URL] and addresses with [EMAIL] tokens.
    - Lowercases and collapses whitespace.
    """
    if not text:
        return ""
    text = re.sub(
        r"<(script|style)\b[^>]*>.*?</\1>", " ", text, flags=re.S | re.I
    )
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"https?://\S+", " [URL] ", text)
    text = re.sub(r"www\.\S+", " [URL] ", text)
    text = re.sub(r"\S+@\S+\.\S+", " [EMAIL] ", text)
    text = re.sub(r"[^a-zA-Z0-9\s\[\].,!?]", " ", text)
    text = text.lower()
    return re.sub(r"\s+", " ", text).strip()
