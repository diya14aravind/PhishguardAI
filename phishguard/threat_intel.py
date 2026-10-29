"""Threat Intelligence Engine: maps agent signals to MITRE ATT&CK techniques,
extracts indicators of compromise (IOCs) and suggests actions."""

from phishguard.domain_utils import registered_domain
from phishguard.parser import host_of

TECHNIQUES = {
    "T1566.001": ("Phishing: Spearphishing Attachment", "Initial Access"),
    "T1566.002": ("Phishing: Spearphishing Link", "Initial Access"),
    "T1598": ("Phishing for Information", "Reconnaissance"),
    "T1598.003": ("Phishing for Information: Spearphishing Link", "Reconnaissance"),
    "T1204.001": ("User Execution: Malicious Link", "Execution"),
    "T1204.002": ("User Execution: Malicious File", "Execution"),
    "T1656": ("Impersonation", "Defense Evasion"),
    "T1036.007": ("Masquerading: Double File Extension", "Defense Evasion"),
    "T1583.001": ("Acquire Infrastructure: Domains", "Resource Development"),
}

URL_SIGNALS = {"url_text_mismatch", "url_ip_host", "url_at_symbol", "url_lookalike", "url_brand_impersonation",
               "url_punycode", "url_shortener", "url_suspicious_tld", "url_redirect_param",
               "url_login_keywords", "url_form_action", "url_script_scheme", "url_many_subdomains"}
LOOKALIKE_SIGNALS = {"url_lookalike", "url_brand_impersonation", "url_punycode", "sender_lookalike_domain",
                     "sender_brand_in_domain", "sender_punycode"}
ATTACHMENT_SIGNALS = {"attach_executable", "attach_disguised_executable", "attach_macro_document",
                      "attach_archive_executable", "attach_html", "attach_pdf_active_content",
                      "attach_disk_image", "attach_encrypted_archive"}
IMPERSONATION_SIGNALS = {"sender_display_brand_mismatch", "sender_display_address_mismatch",
                         "sender_free_mail_authority", "sender_lookalike_domain", "sender_brand_in_domain"}


def build_intel(email, results, fusion):
    all_signals = set()
    for result in results.values():
        all_signals.update(result.signals)
    categories = set(results["social"].details.get("categories", []))

    tags = {}

    def tag(technique_id, evidence):
        if technique_id not in tags:
            tags[technique_id] = {
                "id": technique_id,
                "name": TECHNIQUES[technique_id][0],
                "tactic": TECHNIQUES[technique_id][1],
                "url": "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/",
                "evidence": evidence,
            }

    if fusion["verdict"] in ("SUSPICIOUS", "PHISHING"):
        link_hits = sorted(all_signals & URL_SIGNALS)
        if link_hits:
            tag("T1566.002", "Link indicators: " + ", ".join(link_hits))
            tag("T1204.001", "The email relies on the recipient clicking a link.")
            if "credential" in categories:
                tag("T1598.003", "Link plus a request for credentials or personal details.")
        elif "credential" in categories:
            tag("T1598", "Asks the recipient for credentials or personal details.")

        attachment_hits = sorted(all_signals & ATTACHMENT_SIGNALS)
        if attachment_hits:
            tag("T1566.001", "Attachment indicators: " + ", ".join(attachment_hits))
            tag("T1204.002", "The email relies on the recipient opening a file.")
        if "attach_double_extension" in all_signals:
            tag("T1036.007", "Attachment name uses a double extension.")

        lookalike_hits = sorted(all_signals & LOOKALIKE_SIGNALS)
        if lookalike_hits:
            tag("T1583.001", "Look-alike domain indicators: " + ", ".join(lookalike_hits) + " (attacker-registered domain is likely).")

        impersonation_hits = sorted(all_signals & IMPERSONATION_SIGNALS)
        if impersonation_hits or fusion["bec_tier"] >= 1:
            evidence = "Sender impersonation indicators: " + ", ".join(impersonation_hits)
            if fusion["bec_tier"] >= 1:
                evidence = "Business Email Compromise pattern (tier " + str(fusion["bec_tier"]) + ")."
            tag("T1656", evidence)

    return {
        "mitre_attack": list(tags.values()),
        "iocs": _extract_iocs(email),
        "recommendations": _recommendations(fusion, all_signals),
    }


def _extract_iocs(email):
    urls = []
    domains = []
    for link in email.links:
        urls.append(link.href)
        host = host_of(link.href)
        if host:
            domain = registered_domain(host)
            if domain not in domains:
                domains.append(domain)
    sender_domain = ""
    if email.from_addr:
        sender_domain = registered_domain(email.from_addr.split("@")[-1])
    return {
        "sender_address": email.from_addr,
        "sender_domain": sender_domain,
        "reply_to": email.reply_to_addr,
        "urls": urls[:25],
        "domains": domains[:25],
        "attachment_hashes": [
            {"filename": item.filename, "sha256": item.sha256} for item in email.attachments
        ],
    }


def _recommendations(fusion, signals):
    verdict = fusion["verdict"]
    if verdict == "SAFE":
        return ["No action needed. Stay careful with unexpected requests for money or credentials."]
    if verdict == "SPAM":
        return ["Mark as spam or unsubscribe through the sender's official site, not through links in this email.",
                "Do not reply."]

    steps = []
    if verdict == "PHISHING":
        steps.append("Do not click links, open attachments or reply.")
    else:
        steps.append("Treat with caution. Verify the sender through a separate channel before acting.")
    if fusion["bec_tier"] >= 1:
        steps.append("Confirm any payment or bank detail change by phoning a number you already trust.")
    if signals & URL_SIGNALS:
        steps.append("If you already clicked, change the password for that service and enable multi-factor authentication.")
    if signals & ATTACHMENT_SIGNALS or "attach_double_extension" in signals:
        steps.append("If you opened the attachment, disconnect from the network and run a malware scan.")
    steps.append("Report the message to your IT or security team and delete it.")
    return steps
