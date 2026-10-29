import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from phishguard.domain_utils import check_brand_abuse, registered_domain
from phishguard.parser import parse_email
from phishguard.pipeline import PhishGuardPipeline

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

EXPECTED = {
    "legit_meeting.eml": "SAFE",
    "legit_security_alert.eml": "SAFE",
    "spam_promo.eml": "SPAM",
    "phish_paypal.eml": "PHISHING",
    "malware_invoice.eml": "PHISHING",
    "bec_wire.eml": "PHISHING",
    "bec_tier1_invoice.eml": "SUSPICIOUS",
}


@pytest.fixture(scope="module")
def pipeline():
    return PhishGuardPipeline()


@pytest.mark.parametrize("name,expected", sorted(EXPECTED.items()))
def test_sample_verdicts(pipeline, name, expected):
    report = pipeline.analyze_raw((SAMPLES / name).read_bytes())
    assert report["verdict"] == expected


def test_bec_tiers(pipeline):
    tier2 = pipeline.analyze_raw((SAMPLES / "bec_wire.eml").read_bytes())
    tier1 = pipeline.analyze_raw((SAMPLES / "bec_tier1_invoice.eml").read_bytes())
    assert tier2["fusion"]["bec_tier"] == 2
    assert tier1["fusion"]["bec_tier"] == 1


def test_spam_is_not_called_phishing(pipeline):
    report = pipeline.analyze_raw((SAMPLES / "spam_promo.eml").read_bytes())
    assert report["fusion"]["risk_score"] < 0.45
    assert report["threat_intel"]["mitre_attack"] == []


def test_double_extension_attachment_found(pipeline):
    report = pipeline.analyze_raw((SAMPLES / "malware_invoice.eml").read_bytes())
    assert "attach_double_extension" in report["agents"]["attachment"]["signals"]
    assert report["agents"]["attachment"]["details"]["attachments"][0]["sha256"]


def test_pasted_body_without_headers(pipeline):
    report = pipeline.analyze_raw("Hi, are we still meeting tomorrow to demo the project?")
    assert report["verdict"] == "SAFE"
    assert report["email"]["has_headers"] is False


def test_pasted_credential_request_is_flagged(pipeline):
    text = ("Dear user, your account has been suspended. Verify your password immediately "
            "at http://secure-login.example.xyz/verify to restore access.")
    report = pipeline.analyze_raw(text)
    assert report["verdict"] in ("SUSPICIOUS", "PHISHING")


def test_html_link_text_mismatch():
    email = parse_email('From: a@b.com\nSubject: x\nContent-Type: text/html\n\n'
                        '<a href="http://evil.example.tk/x">www.paypal.com</a>')
    assert email.links[0].anchor_text == "www.paypal.com"


def test_domain_helpers():
    assert registered_domain("mail.example.co.uk") == "example.co.uk"
    assert check_brand_abuse("paypa1.com") == ("lookalike", "paypal")
    assert check_brand_abuse("paypal.com.evil.net") == ("brand_in_host", "paypal")
    assert check_brand_abuse("accounts.google.com") == (None, None)
