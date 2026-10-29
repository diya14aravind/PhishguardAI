import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("PHISHGUARD_DATA_DIR", BASE_DIR / "data"))
MODEL_DIR = Path(os.environ.get("PHISHGUARD_MODEL_DIR", BASE_DIR / "models"))

LR_MODEL_PATH = MODEL_DIR / "content_lr.joblib"
TRANSFORMER_DIR = MODEL_DIR / "transformer"

# Decision fusion weights (must add up to 1.0)
FUSION_WEIGHTS = {
    "content": 0.30,
    "url": 0.25,
    "sender": 0.20,
    "attachment": 0.15,
    "social": 0.10,
}

# Verdict thresholds on the composite risk score (0 to 1)
PHISHING_THRESHOLD = 0.55
SUSPICIOUS_THRESHOLD = 0.30

# Spam is decided separately from phishing
SPAM_THRESHOLD = 0.50
SPAM_MAX_RISK = 0.45

# If one evidence agent (url, sender, attachment) finds hard evidence, the composite cannot stay low.
# The content model is excluded on purpose: a text classifier alone should not decide a verdict.
EVIDENCE_AGENTS = ("url", "sender", "attachment")
STRONG_SIGNAL_SCORE = 0.85
STRONG_SIGNAL_FLOOR = 0.60
# Text-only rule: strong text model plus an explicit ask for credentials or money
TEXT_COMBO_CONTENT_SCORE = 0.80
TEXT_COMBO_SOCIAL_SCORE = 0.50
TEXT_COMBO_FLOOR = 0.55

# Classic phishing signature: asks for credentials or money AND carries a suspicious link
ASK_WITH_LINK_URL_SCORE = 0.40
ASK_WITH_LINK_FLOOR = 0.55

CORROBORATION_SCORE = 0.40
CORROBORATION_BONUS = 0.10

# Mail that passes DMARC from a known brand domain, with clean links and attachments, is capped low
TRUSTED_ORIGIN_CAP = 0.20

# Business Email Compromise escalation floors
BEC_TIER1_FLOOR = 0.45
BEC_TIER2_FLOOR = 0.80

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
