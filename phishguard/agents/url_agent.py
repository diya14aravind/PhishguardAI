import re
from urllib.parse import parse_qs, urlparse

from phishguard.agents.base import AgentResult, noisy_or
from phishguard.domain_utils import (
    ALL_LEGIT_DOMAINS, SUSPICIOUS_TLDS, URL_SHORTENERS, check_brand_abuse,
    is_ip_address, registered_domain, tld_of,
)
from phishguard.parser import host_of

PATH_KEYWORDS = ["login", "signin", "sign-in", "verify", "secure", "account", "update",
                 "confirm", "password", "banking", "webscr", "auth", "wallet", "recover"]
DOMAIN_TEXT = re.compile(r"(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}", re.IGNORECASE)


class URLAgent:
    name = "url"

    def analyze(self, email):
        result = AgentResult(name=self.name)
        if not email.links:
            result.findings.append("No links found in the email.")
            return result

        url_reports = []
        for link in email.links:
            url_reports.append(self._analyze_link(link))

        scores = [report["score"] for report in url_reports]
        suspicious_count = len([s for s in scores if s >= 0.4])
        top_score = max(scores)
        result.score = min(1.0, top_score + 0.05 * max(0, suspicious_count - 1))

        for report in url_reports:
            if report["score"] >= 0.3:
                for finding in report["findings"]:
                    result.findings.append(report["url"][:80] + ": " + finding)
            for code in report["signals"]:
                if code not in result.signals:
                    result.signals.append(code)

        if not result.findings:
            result.findings.append("Links look ordinary (" + str(len(email.links)) + " checked, no red flags).")
        result.details["links"] = url_reports
        return result

    def _analyze_link(self, link):
        url = link.href
        findings = []
        signals = []
        weights = []

        def flag(code, weight, text):
            signals.append(code)
            weights.append(weight)
            findings.append(text)

        lowered = url.lower()
        if lowered.startswith("javascript:") or lowered.startswith("data:"):
            flag("url_script_scheme", 0.6, "Link uses a script or data scheme instead of a web address.")
            return self._report(link, "", weights, findings, signals)
        if lowered.startswith("mailto:") or lowered.startswith("tel:"):
            return self._report(link, "", [], [], [])

        host = host_of(url)
        reg = registered_domain(host)
        trusted = reg in ALL_LEGIT_DOMAINS

        # Anchor text that shows one domain while the href goes to another
        anchor = link.anchor_text.strip()
        if anchor and DOMAIN_TEXT.search(anchor):
            shown_host = host_of(DOMAIN_TEXT.search(anchor).group(0))
            if shown_host and registered_domain(shown_host) != reg:
                flag("url_text_mismatch", 0.70,
                     "Link text shows '" + shown_host + "' but it really goes to '" + host + "'.")

        if is_ip_address(host):
            flag("url_ip_host", 0.60, "Link points to a raw IP address.")

        if "@" in urlparse(url if "://" in url else "http://" + url).netloc:
            flag("url_at_symbol", 0.50, "Link contains an '@' that hides the real destination.")

        if not trusted:
            self._untrusted_checks(url, host, reg, flag)

        if link.source == "form" and not trusted:
            flag("url_form_action", 0.20, "A form in the email submits data to an outside site.")

        return self._report(link, host, weights, findings, signals)

    def _untrusted_checks(self, url, host, reg, flag):
        if "xn--" in host:
            flag("url_punycode", 0.45, "Domain uses punycode, which can hide lookalike characters.")

        kind, brand = check_brand_abuse(host)
        if kind == "lookalike":
            flag("url_lookalike", 0.75, "Domain looks like a copy of '" + brand + "'.")
        elif kind == "brand_in_host":
            flag("url_brand_impersonation", 0.60, "Domain uses the name '" + brand + "' but is not owned by it.")

        if reg in URL_SHORTENERS:
            flag("url_shortener", 0.25, "Link uses a URL shortener that hides the destination.")

        if tld_of(host) in SUSPICIOUS_TLDS:
            flag("url_suspicious_tld", 0.30, "Domain ends in '." + tld_of(host) + "', common in abuse.")

        extra_labels = len(host.split(".")) - len(reg.split("."))
        if extra_labels >= 3:
            flag("url_many_subdomains", 0.25, "Link has an unusually deep subdomain chain.")

        if host.count("-") >= 3:
            flag("url_many_hyphens", 0.20, "Domain has many hyphens.")

        if len(url) > 100:
            flag("url_long", 0.10, "Link is very long.")

        parsed = urlparse(url if "://" in url else "http://" + url)
        if parsed.scheme == "http":
            flag("url_no_https", 0.15, "Link does not use HTTPS.")
        if parsed.port is not None and parsed.port not in (80, 443):
            flag("url_odd_port", 0.15, "Link uses an unusual port.")

        path_and_query = (parsed.path + "?" + parsed.query).lower()
        keyword_hits = len([word for word in PATH_KEYWORDS if word in path_and_query])
        if keyword_hits >= 2:
            flag("url_login_keywords", 0.25, "Link path asks for login or verification.")
        elif keyword_hits == 1:
            flag("url_login_keywords", 0.15, "Link path mentions login or verification.")

        for values in parse_qs(parsed.query).values():
            for value in values:
                if value.lower().startswith("http"):
                    flag("url_redirect_param", 0.25, "Link passes another URL as a parameter (open redirect).")

    def _report(self, link, host, weights, findings, signals):
        return {
            "url": link.href,
            "host": host,
            "score": round(noisy_or(weights), 3),
            "findings": findings,
            "signals": signals,
        }
