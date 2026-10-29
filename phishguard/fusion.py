from phishguard import config
from phishguard.agents.sender import IDENTITY_DECEPTION_SIGNALS
from phishguard.domain_utils import ALL_LEGIT_DOMAINS, registered_domain

AGENT_LABELS = {
    "content": "Content",
    "url": "URL Intelligence",
    "sender": "Sender Verification",
    "attachment": "Attachment Analysis",
    "social": "Social Engineering",
}


def fuse(results, email):
    """Combine the five agent results into one verdict.

    Steps:
      1. weighted sum of agent scores
      2. strong signal floor (one agent with hard evidence keeps the score up)
      3. corroboration bonus (two or more agents agree)
      4. two-tier BEC escalation
      5. verdict, with spam handled separately from phishing
    """
    scores = {}
    for name in config.FUSION_WEIGHTS:
        scores[name] = results[name].score

    contributions = {}
    composite = 0.0
    for name, weight in config.FUSION_WEIGHTS.items():
        contributions[name] = round(weight * scores[name], 4)
        composite += weight * scores[name]

    reasons = []

    strongest_agent = max(config.EVIDENCE_AGENTS, key=lambda name: scores[name])
    if scores[strongest_agent] >= config.STRONG_SIGNAL_SCORE:
        if composite < config.STRONG_SIGNAL_FLOOR:
            composite = config.STRONG_SIGNAL_FLOOR
            reasons.append("Strong evidence from the " + AGENT_LABELS[strongest_agent] + " agent raised the score.")

    social_categories = set(results["social"].details.get("categories", []))
    explicit_ask = len(social_categories & {"credential", "payment"}) > 0
    text_model_strong = scores["content"] >= config.TEXT_COMBO_CONTENT_SCORE
    wording_strong = scores["social"] >= config.TEXT_COMBO_SOCIAL_SCORE
    if text_model_strong and wording_strong and explicit_ask:
        if composite < config.TEXT_COMBO_FLOOR:
            composite = config.TEXT_COMBO_FLOOR
            reasons.append("The text model and the wording analysis both point to a request for credentials or money.")

    if explicit_ask and "reward" in social_categories:
        if composite < config.TEXT_COMBO_FLOOR:
            composite = config.TEXT_COMBO_FLOOR
            reasons.append("A prize or reward offer is combined with a request for details or payment (advance-fee scam pattern).")

    if explicit_ask and scores["url"] >= config.ASK_WITH_LINK_URL_SCORE:
        if composite < config.ASK_WITH_LINK_FLOOR:
            composite = config.ASK_WITH_LINK_FLOOR
            reasons.append("The email asks for credentials or money and contains a suspicious link.")

    agreeing = [name for name in scores if scores[name] >= config.CORROBORATION_SCORE]
    if len(agreeing) >= 2:
        composite += config.CORROBORATION_BONUS
        reasons.append(str(len(agreeing)) + " agents independently found risk, which raised confidence.")

    bec_tier = _bec_tier(results, email)
    if bec_tier == 1 and composite < config.BEC_TIER1_FLOOR:
        composite = config.BEC_TIER1_FLOOR
        reasons.append("BEC pattern: money or availability request with pressure and no technical red flags.")
    if bec_tier == 2:
        if composite < config.BEC_TIER2_FLOOR:
            composite = config.BEC_TIER2_FLOOR
        reasons.append("BEC pattern confirmed: payment pressure combined with a spoofed or mismatched sender identity.")

    if bec_tier == 0 and _trusted_origin(results, email):
        if composite > config.TRUSTED_ORIGIN_CAP:
            composite = config.TRUSTED_ORIGIN_CAP
            reasons.append("Passed DMARC from a known brand domain with clean links, so the score was capped.")

    composite = max(0.0, min(1.0, composite))

    spam_probability = results["content"].details.get("spam_probability", 0.0)
    verdict = _verdict(composite, spam_probability, bec_tier)

    for name in sorted(scores, key=scores.get, reverse=True):
        if scores[name] >= 0.3:
            reasons.append(AGENT_LABELS[name] + " agent score " + str(round(100 * scores[name])) + "%.")

    return {
        "verdict": verdict,
        "risk_score": round(composite, 3),
        "risk_percent": round(100 * composite),
        "spam_probability": round(spam_probability, 3),
        "bec_tier": bec_tier,
        "agent_scores": {name: round(value, 3) for name, value in scores.items()},
        "weighted_contributions": contributions,
        "reasons": reasons,
        "limitations": _limitations(results, email),
    }


def _bec_tier(results, email):
    social_categories = set(results["social"].details.get("categories", []))
    money_or_probe = "payment" in social_categories or "rapport" in social_categories
    pressure = len(social_categories & {"urgency", "secrecy", "authority"}) > 0
    if not (money_or_probe and pressure):
        return 0

    # Links or risky attachments point to ordinary phishing, not BEC
    if results["attachment"].score >= 0.6:
        return 0

    sender_signals = set(results["sender"].signals)
    if sender_signals & IDENTITY_DECEPTION_SIGNALS:
        return 2
    return 1


def _verdict(composite, spam_probability, bec_tier):
    if bec_tier == 2:
        return "PHISHING"
    if composite >= config.PHISHING_THRESHOLD:
        return "PHISHING"
    if spam_probability >= config.SPAM_THRESHOLD and composite < config.SPAM_MAX_RISK:
        return "SPAM"
    if composite >= config.SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    return "SAFE"


def _limitations(results, email):
    notes = []
    if not email.has_headers:
        notes.append("No headers supplied: sender authentication was not checked. "
                     "Upload the .eml or paste the full source for a complete result.")
    backend = results["content"].details.get("backend")
    if backend == "heuristic":
        notes.append("Content model not trained yet: keyword fallback in use.")
    if results["url"].details.get("links"):
        notes.append("URLs are analysed offline (structure and lookalike checks). No live reputation lookup is made.")
    return notes


def _trusted_origin(results, email):
    if not email.has_headers or not email.from_addr:
        return False
    from_domain = registered_domain(email.from_addr.split("@")[-1])
    if from_domain not in ALL_LEGIT_DOMAINS:
        return False
    if results["sender"].details.get("dmarc") != "pass":
        return False
    if results["sender"].signals:
        return False
    if results["url"].score >= 0.1 or results["attachment"].score >= 0.1:
        return False
    return True
