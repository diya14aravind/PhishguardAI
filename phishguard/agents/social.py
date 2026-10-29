import re

from phishguard.agents.base import AgentResult, noisy_or

# category -> (base weight, label, patterns)
CATEGORIES = {
    "urgency": (0.30, "Urgency", [
        r"\burgent(ly)?\b", r"\bimmediately\b", r"\basap\b", r"\bright away\b",
        r"\bwithin \d+ (hours?|minutes?|days?)\b", r"\bact now\b", r"\bfinal (notice|warning)\b",
        r"\blast (warning|chance)\b", r"\bexpires? (today|soon|in)\b", r"\btime[- ]sensitive\b",
        r"\bas soon as possible\b", r"\bdeadline\b"]),
    "fear": (0.35, "Fear or threat", [
        r"account (will be|has been|was) (suspended|closed|locked|limited|terminated|disabled|deactivated)",
        r"\bunauthori[sz]ed (access|login|transaction|activity|sign[- ]?in)\b", r"\blegal action\b",
        r"\bsuspicious (activity|login|sign[- ]?in)\b", r"\bsecurity alert\b", r"\bwill be (deleted|removed|terminated)\b",
        r"\bfailure to (comply|respond|verify|update)\b", r"\bpermanently (closed|locked|disabled)\b"]),
    "authority": (0.20, "Authority claim", [
        r"\b(ceo|cfo|coo|chief executive|managing director|chairman|president)\b",
        r"\b(hr|human resources|it|payroll|compliance|security|accounts|finance) (department|team|desk|office)\b",
        r"\bhelp ?desk\b", r"\b(irs|income tax|police|court|government)\b"]),
    "reward": (0.30, "Reward or greed", [
        r"\byou('ve| have) (won|been selected)\b", r"\bwinner\b", r"\bprize\b", r"\blottery\b",
        r"\bcongratulations\b", r"\bclaim your\b", r"\bfree (gift|iphone|ticket|voucher)\b",
        r"\binheritance\b", r"\b\d+ (million|billion) (dollars|usd|pounds)\b", r"\bunclaimed (funds|refund)\b"]),
    "credential": (0.40, "Credential request", [
        r"\b(verify|confirm|update|validate|re-?enter) your (account|password|identity|credentials|information|details|payment|billing|bank|email)\b",
        r"\b(enter|provide|send|share|reply with) (me )?your (password|otp|pin|ssn|card number|cvv|login|username)\b",
        r"\bclick (here|the link( below)?|below) to (verify|log ?in|sign ?in|confirm|update|unlock|restore)\b",
        r"\b(send(ing)?|shar(e|ing)|provid(e|ing)|giv(e|ing)|reply(ing)? with) (me |us )?(your )?(bank|account|card|payment)( account)? (details|number|information)\b",
        r"\b(complete|update|verify|submit) (your )?(kyc|pan|aadhaar|aadhar)\b",
        r"\bsign ?in with your (office |work |company |corporate |school |university )?(email|account|credentials)\b",
        r"\bkeep (the same|your current) password\b", r"\bpassword (expires?|will expire)\b",
        r"\bconfirm your (address|delivery)\b",
        r"\bsign ?in to (your|view|review)\b", r"\bone[- ]time (password|code)\b"]),
    "payment": (0.40, "Payment or transfer request", [
        r"\bwire transfer\b", r"\bbank transfer\b", r"\bgift cards?\b", r"\bitunes cards?\b",
        r"\b(bitcoin|btc|crypto(currency)?|western union|moneygram)\b",
        r"\b(change|update) (of )?(my |our |the )?(bank|account|payment) (details|number|information)\b",
        r"\bnew (bank|account) (details|number)\b", r"\boverdue (invoice|payment)\b",
        r"\b(process|make|send|arrange) (a|the|this) (payment|transfer)\b",
        r"\bpay (a )?(small |nominal )?(fee|charge|amount)\b", r"\b(unpaid )?(customs|redelivery|delivery) fee\b", r"\bpay(ment)? (is )?(pending|overdue|due)\b"]),
    "secrecy": (0.30, "Secrecy", [
        r"\bkeep this (confidential|between us|private|secret)\b", r"\bdo(n't| not) (tell|share|discuss|mention)\b",
        r"\bstrictly confidential\b", r"\bdon'?t (call|phone) me\b", r"\bonly you\b"]),
    "rapport": (0.25, "Availability probe", [
        r"\bare you (available|at your desk|free|around)\b", r"\bdo you have a (minute|moment)\b",
        r"\bneed a (quick )?favou?r\b", r"\bi('m| am) (in a meeting|travell?ing|unable to (talk|call))\b",
        r"\breply (only )?(by|via|on) email\b", r"\bkindly (get back|reply|respond)\b"]),
    "generic": (0.15, "Generic greeting", [
        r"\bdear (customer|user|client|member|account holder|sir|madam|sir/madam|valued [a-z]+|friend|beneficiary)\b"]),
}


class SocialEngineeringAgent:
    name = "social"

    def analyze(self, email):
        result = AgentResult(name=self.name)
        text = ((email.subject or "") + " . " + (email.body_text or "")).lower()
        weights = []
        tactics = {}

        for key, (base_weight, label, patterns) in CATEGORIES.items():
            matches = []
            for pattern in patterns:
                found = re.search(pattern, text, re.IGNORECASE)
                if found:
                    matches.append(found.group(0))
            if not matches:
                continue
            weight = base_weight
            if len(matches) >= 2:
                weight = min(0.9, base_weight + 0.10)
            weights.append(weight)
            tactics[key] = matches[:3]
            result.signals.append("social_" + key)
            result.findings.append(label + ": " + ", ".join("'" + m + "'" for m in matches[:3]) + ".")

        result.score = noisy_or(weights)
        result.details["categories"] = sorted(tactics.keys())
        result.details["matches"] = tactics
        if not result.findings:
            result.findings.append("No pressure or manipulation tactics detected.")
        return result
