import re

URL_PATTERN = re.compile(r"(https?://[^\s<>\"')\]]+|www\.[^\s<>\"')\]]+)", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def clean_text(text):
    """Normalise text the same way for training and prediction."""
    text = text or ""
    text = URL_PATTERN.sub(" urltoken ", text)
    text = EMAIL_PATTERN.sub(" emailtoken ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip().lower()


def build_model_text(subject, body):
    """Subject and body are joined into one string for the content model."""
    return clean_text((subject or "") + " . " + (body or ""))
