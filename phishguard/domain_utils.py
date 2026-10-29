import ipaddress
import re

MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.in", "net.in",
    "ac.in", "gov.in", "org.in", "co.jp", "com.br", "co.za", "com.sg", "com.cn",
    "co.nz", "com.mx", "com.tr", "edu.in", "res.in",
}

FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com", "live.com",
    "aol.com", "icloud.com", "proton.me", "protonmail.com", "mail.com", "gmx.com",
    "yandex.com", "rediffmail.com", "zoho.com",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "link", "zip", "mov",
    "icu", "buzz", "cyou", "rest", "loan", "work", "country", "support", "cam", "monster",
}

# brand name -> registered domains that really belong to it
BRANDS = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com", "office365.com",
                  "microsoftonline.com", "sharepoint.com", "windows.com", "azure.com"},
    "google": {"google.com", "gmail.com", "googleapis.com", "goo.gl", "youtube.com", "gstatic.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com", "amazon.ca"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com", "instagram.com", "facebookmail.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "paytm": {"paytm.com"},
    "flipkart": {"flipkart.com"},
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    "axisbank": {"axisbank.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "github": {"github.com", "github.io", "githubusercontent.com"},
    "zoom": {"zoom.us"},
    "adobe": {"adobe.com"},
    "whatsapp": {"whatsapp.com"},
    "twitter": {"twitter.com", "x.com"},
    "vit": {"vit.ac.in", "vitap.ac.in"},
}

ALL_LEGIT_DOMAINS = set()
for _domains in BRANDS.values():
    ALL_LEGIT_DOMAINS.update(_domains)

HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("$", "s")]


def is_ip_address(host):
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Decimal or hex forms such as http://3232235777/ or http://0xC0A80001/
    if re.fullmatch(r"\d{8,10}", host) or re.fullmatch(r"0x[0-9a-fA-F]+", host):
        return True
    return False


def registered_domain(host):
    host = (host or "").lower().strip(".")
    if not host or is_ip_address(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return last_two


def domain_label(reg_domain):
    """The name part of a registered domain, e.g. paypal from paypal.com."""
    reg_domain = reg_domain or ""
    labels = reg_domain.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return labels[-3]
    return labels[0]


def tld_of(host):
    labels = (host or "").lower().split(".")
    return labels[-1]


def levenshtein(a, b):
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1]
            if char_a != char_b:
                replace_cost += 1
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current
    return previous[-1]


def normalise_homoglyphs(label):
    label = label.lower()
    for fake, real in HOMOGLYPHS:
        label = label.replace(fake, real)
    return label


def check_brand_abuse(host):
    """Return (kind, brand) if the host imitates a known brand, else (None, None).

    kind is one of: lookalike, brand_in_host
    """
    host = (host or "").lower()
    reg = registered_domain(host)
    if reg in ALL_LEGIT_DOMAINS:
        return None, None
    label = domain_label(reg)
    normalised = normalise_homoglyphs(label)

    for brand in BRANDS:
        if len(brand) < 4:
            continue
        # paypa1.com, rnicrosoft.com, paypall.com
        if label != brand:
            if normalised == brand:
                return "lookalike", brand
            if len(brand) >= 6 and levenshtein(normalised, brand) == 1:
                return "lookalike", brand
            # paypa1-secure.com: brand only appears after undoing look-alike characters
            if brand in normalised and brand not in label:
                return "lookalike", brand
        # paypal-secure.com, paypal.com.evil.net, secure-paypal.xyz
        if brand in host:
            return "brand_in_host", brand
    return None, None
