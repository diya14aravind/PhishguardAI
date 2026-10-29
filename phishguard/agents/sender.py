import re

from phishguard.agents.base import AgentResult, noisy_or
from phishguard.domain_utils import (
    ALL_LEGIT_DOMAINS, BRANDS, FREE_MAIL_DOMAINS, SUSPICIOUS_TLDS, check_brand_abuse,
    registered_domain, tld_of,
)

AUTHORITY_WORDS = ["ceo", "cfo", "coo", "director", "president", "chairman", "hr", "payroll",
                   "it support", "helpdesk", "help desk", "admin", "security", "accounts", "finance"]

# Signals that mean the sender is pretending to be someone else (used for BEC tier 2)
IDENTITY_DECEPTION_SIGNALS = {
    "sender_display_brand_mismatch", "sender_display_address_mismatch", "sender_lookalike_domain",
    "sender_brand_in_domain", "sender_free_mail_authority", "sender_reply_to_free_mail",
    "sender_reply_to_mismatch", "sender_dmarc_fail", "sender_spf_fail", "sender_dkim_fail",
    "sender_punycode",
}


def _auth_result(text, mechanism):
    match = re.search(mechanism + r"\s*=\s*(\w+)", text or "", re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return None


class SenderAgent:
    name = "sender"

    def analyze(self, email):
        result = AgentResult(name=self.name)
        weights = []

        def flag(code, weight, text):
            result.signals.append(code)
            weights.append(weight)
            result.findings.append(text)

        if not email.has_headers:
            result.findings.append("No email headers were supplied, so sender checks were skipped. "
                                   "Paste the full source or upload the .eml for a complete check.")
            result.details["header_check"] = "skipped"
            return result

        if not email.from_addr:
            flag("sender_missing", 0.40, "The message has no readable From address.")
            result.score = noisy_or(weights)
            return result

        from_domain = email.from_addr.split("@")[-1]
        from_reg = registered_domain(from_domain)
        display = (email.from_name or "").lower()

        self._authentication(email, flag, result)
        self._display_name(email, display, from_domain, from_reg, flag)
        self._domain_checks(from_domain, from_reg, flag)
        self._reply_and_return_path(email, from_reg, flag, result)

        result.score = noisy_or(weights)
        result.details["from"] = email.from_addr
        result.details["display_name"] = email.from_name
        result.details["reply_to"] = email.reply_to_addr
        if not result.findings:
            result.findings.append("Sender checks found nothing unusual.")
        return result

    def _authentication(self, email, flag, result):
        auth_text = email.auth_results
        spf = _auth_result(auth_text, "spf")
        dkim = _auth_result(auth_text, "dkim")
        dmarc = _auth_result(auth_text, "dmarc")
        if spf is None and email.received_spf:
            first_word = email.received_spf.strip().split(" ")[0].lower()
            spf = first_word
        result.details["spf"] = spf
        result.details["dkim"] = dkim
        result.details["dmarc"] = dmarc

        if spf == "fail":
            flag("sender_spf_fail", 0.40, "SPF failed: the sending server is not allowed to send for this domain.")
        elif spf == "softfail":
            flag("sender_spf_fail", 0.25, "SPF soft-failed for this sender domain.")
        if dkim == "fail":
            flag("sender_dkim_fail", 0.35, "DKIM signature failed verification.")
        if dmarc == "fail":
            flag("sender_dmarc_fail", 0.45, "DMARC failed for this sender domain.")

        if spf is None and dkim is None and dmarc is None:
            result.findings.append("No SPF, DKIM or DMARC results in the headers (nothing to verify).")
            result.details["auth"] = "unavailable"
        elif spf == "pass" or dkim == "pass" or dmarc == "pass":
            result.details["auth"] = "pass"

    def _display_name(self, email, display, from_domain, from_reg, flag):
        if "@" in display:
            shown_domain = display.split("@")[-1].strip(" >\"'")
            if registered_domain(shown_domain) != from_reg:
                flag("sender_display_address_mismatch", 0.60,
                     "Display name shows an address on a different domain than the real sender.")

        for brand, legit_domains in BRANDS.items():
            if len(brand) < 4:
                continue
            if brand in display.replace(" ", "") and from_reg not in legit_domains:
                flag("sender_display_brand_mismatch", 0.65,
                     "Display name claims to be '" + brand + "' but the address is on " + from_reg + ".")
                break

        if from_reg in FREE_MAIL_DOMAINS:
            for word in AUTHORITY_WORDS:
                if re.search(r"\b" + re.escape(word) + r"\b", display):
                    flag("sender_free_mail_authority", 0.50,
                         "Display name suggests an official role but the address is a free mail account.")
                    break

    def _domain_checks(self, from_domain, from_reg, flag):
        if "xn--" in from_domain:
            flag("sender_punycode", 0.50, "Sender domain uses punycode (possible lookalike characters).")
        kind, brand = check_brand_abuse(from_domain)
        if kind == "lookalike":
            flag("sender_lookalike_domain", 0.70, "Sender domain looks like a copy of '" + brand + "'.")
        elif kind == "brand_in_host":
            flag("sender_brand_in_domain", 0.55, "Sender domain uses the name '" + brand + "' but is not owned by it.")
        if tld_of(from_domain) in SUSPICIOUS_TLDS:
            flag("sender_suspicious_tld", 0.25, "Sender domain ends in '." + tld_of(from_domain) + "'.")

    def _reply_and_return_path(self, email, from_reg, flag, result):
        if email.reply_to_addr:
            reply_reg = registered_domain(email.reply_to_addr.split("@")[-1])
            if reply_reg != from_reg:
                if reply_reg in FREE_MAIL_DOMAINS and from_reg not in FREE_MAIL_DOMAINS:
                    flag("sender_reply_to_free_mail", 0.50,
                         "Replies go to a free mail account instead of the sending organisation.")
                else:
                    flag("sender_reply_to_mismatch", 0.35,
                         "Reply-To domain (" + reply_reg + ") differs from the sender domain.")

        if email.return_path_addr and result.details.get("auth") != "pass":
            return_reg = registered_domain(email.return_path_addr.split("@")[-1])
            if return_reg != from_reg:
                flag("sender_return_path_mismatch", 0.15, "Return-Path domain differs from the sender domain.")
