import re

import joblib

from phishguard.agents.base import AgentResult
from phishguard.config import LR_MODEL_PATH, TRANSFORMER_DIR
from phishguard.text_utils import build_model_text

PHISH_WORDS = [
    r"verify your (account|identity|email)", r"confirm your (account|identity|password)", r"password",
    r"log ?in", r"sign ?in", r"suspended", r"unusual activity", r"security (alert|check)",
    r"bank account", r"credit card", r"social security", r"click (here|below)", r"update your",
    r"billing (information|details)", r"limited access", r"validate",
]
SPAM_WORDS = [
    r"\bfree\b", r"\bwinner\b", r"\b\d+% off\b", r"\bdiscount\b", r"\bsale\b", r"limited time",
    r"\bbuy now\b", r"\border now\b", r"\bunsubscribe\b", r"\bcoupon\b", r"\bdeal\b", r"\bpromo(tion|tional)?\b",
    r"\boffer\b", r"\bexclusive\b", r"\bsave (up to|big)\b", r"\bcheap\b", r"\bviagra\b", r"\bcasino\b",
    r"\bno obligation\b", r"\bclick here\b", r"\bshop now\b", r"\bbest price\b",
]


def _keyword_score(text, patterns, step):
    hits = 0
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            hits += 1
    return min(1.0, hits * step)


class ContentAgent:
    """Text classifier. Uses a transformer if present, else TF-IDF + Logistic Regression,
    else a keyword fallback so the system still runs before training."""

    name = "content"

    def __init__(self):
        self.backend = "heuristic"
        self.vectorizer = None
        self.classifier = None
        self.labels = []
        self.transformer = None
        self._load()

    def _load(self):
        if TRANSFORMER_DIR.exists() and (TRANSFORMER_DIR / "config.json").exists():
            try:
                from transformers import pipeline as hf_pipeline
                self.transformer = hf_pipeline("text-classification", model=str(TRANSFORMER_DIR),
                                               tokenizer=str(TRANSFORMER_DIR), top_k=None,
                                               truncation=True, max_length=256)
                self.backend = "transformer"
                return
            except Exception as error:
                print("Transformer model could not be loaded (" + str(error) + "). Falling back to Logistic Regression.")

        if LR_MODEL_PATH.exists():
            bundle = joblib.load(LR_MODEL_PATH)
            self.vectorizer = bundle["vectorizer"]
            self.classifier = bundle["classifier"]
            self.labels = list(self.classifier.classes_)
            self.backend = "tfidf_logreg"

    def analyze(self, email):
        result = AgentResult(name=self.name)
        text = build_model_text(email.subject, email.body_text)
        result.details["backend"] = self.backend

        if not text.strip(" ."):
            result.findings.append("The email has no readable text.")
            result.details["probabilities"] = {"ham": 1.0, "phishing": 0.0, "spam": 0.0}
            return result

        heuristic_spam = _keyword_score(text, SPAM_WORDS, 0.18)
        heuristic_phish = _keyword_score(text, PHISH_WORDS, 0.14)

        if self.backend == "transformer":
            probabilities = self._predict_transformer(text)
        elif self.backend == "tfidf_logreg":
            probabilities = self._predict_logreg(text, result)
        else:
            probabilities = {"phishing": heuristic_phish, "spam": heuristic_spam,
                             "ham": max(0.0, 1.0 - max(heuristic_phish, heuristic_spam))}
            result.findings.append("No trained model found, so a keyword fallback was used. "
                                   "Run train.py to enable the machine learning classifier.")

        # The model is trusted most; keyword hints only nudge spam and phishing probabilities.
        if self.backend == "heuristic":
            spam_probability = heuristic_spam
            phishing_probability = probabilities["phishing"]
        else:
            spam_probability = 0.8 * probabilities["spam"] + 0.2 * heuristic_spam
            phishing_probability = probabilities["phishing"]

        result.score = phishing_probability
        result.details["probabilities"] = {k: round(v, 3) for k, v in probabilities.items()}
        result.details["spam_probability"] = round(spam_probability, 3)
        result.details["promo_keyword_score"] = round(heuristic_spam, 3)

        predicted = max(probabilities, key=probabilities.get)
        result.findings.insert(0, "Text classifier (" + self.backend + ") predicts '" + predicted + "' with " +
                               str(round(100 * probabilities[predicted])) + "% confidence.")
        if phishing_probability >= 0.5:
            result.signals.append("content_phishing_language")
        if spam_probability >= 0.5:
            result.signals.append("content_spam_language")
        return result

    def _predict_logreg(self, text, result):
        features = self.vectorizer.transform([text])
        raw = self.classifier.predict_proba(features)[0]
        probabilities = {}
        for label, value in zip(self.labels, raw):
            probabilities[label] = float(value)
        for needed in ("ham", "phishing", "spam"):
            probabilities.setdefault(needed, 0.0)

        predicted = max(probabilities, key=probabilities.get)
        if predicted in self.labels:
            terms = self._top_terms(features, predicted)
            if terms:
                result.details["top_terms"] = terms
                result.findings.append("Words that pushed the prediction toward '" + predicted + "': " + ", ".join(terms) + ".")
        return probabilities

    def _predict_transformer(self, text):
        outputs = self.transformer(text)
        if outputs and isinstance(outputs[0], list):
            outputs = outputs[0]
        probabilities = {"ham": 0.0, "phishing": 0.0, "spam": 0.0}
        for item in outputs:
            probabilities[item["label"].lower()] = float(item["score"])
        return probabilities

    def _top_terms(self, features, label, limit=6):
        class_index = self.labels.index(label)
        coefficients = self.classifier.coef_[class_index]
        names = self.vectorizer.get_feature_names_out()
        coo = features.tocoo()
        contributions = []
        for column, value in zip(coo.col, coo.data):
            contributions.append((names[column], value * coefficients[column]))
        contributions.sort(key=lambda pair: pair[1], reverse=True)
        top = []
        for term, contribution in contributions[:limit]:
            if contribution > 0 and term not in ("urltoken", "emailtoken"):
                top.append(term)
        return top
