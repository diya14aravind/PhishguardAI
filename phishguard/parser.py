import hashlib
import re
from dataclasses import dataclass, field
from email import message_from_bytes, policy
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

from phishguard.text_utils import URL_PATTERN

HEADER_NAMES = {"from", "subject", "date", "received", "message-id", "return-path", "mime-version", "to"}


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size: int
    sha256: str
    data: bytes = field(default=b"", repr=False)


@dataclass
class LinkInfo:
    href: str
    anchor_text: str = ""
    source: str = "text"  # text, html or form


@dataclass
class ParsedEmail:
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    reply_to_addr: str = ""
    return_path_addr: str = ""
    to_addrs: list = field(default_factory=list)
    auth_results: str = ""
    received_spf: str = ""
    body_text: str = ""
    body_html: str = ""
    links: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    has_headers: bool = False


class _HtmlExtractor(HTMLParser):
    """Collects visible text, links with anchor text and form actions."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text_parts = []
        self.links = []
        self._skip_depth = 0
        self._current_href = None
        self._current_anchor = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("script", "style"):
            self._skip_depth += 1
        if tag == "a" and attrs.get("href"):
            self._current_href = attrs["href"].strip()
            self._current_anchor = []
        if tag == "form" and attrs.get("action"):
            self.links.append(LinkInfo(href=attrs["action"].strip(), anchor_text="", source="form"))
        if tag in ("br", "p", "div", "tr", "li"):
            self.text_parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip_depth > 0:
            self._skip_depth -= 1
        if tag == "a" and self._current_href is not None:
            anchor = " ".join("".join(self._current_anchor).split())
            self.links.append(LinkInfo(href=self._current_href, anchor_text=anchor, source="html"))
            self._current_href = None
            self._current_anchor = []

    def handle_data(self, data):
        if self._skip_depth > 0:
            return
        self.text_parts.append(data)
        if self._current_href is not None:
            self._current_anchor.append(data)


def html_to_text(html):
    extractor = _HtmlExtractor()
    try:
        extractor.feed(html)
    except Exception:
        pass
    text = "".join(extractor.text_parts)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n\n", text)
    return text.strip(), extractor.links


def _single_address(value):
    if not value:
        return "", ""
    name, address = parseaddr(str(value))
    return name.strip(), address.strip().lower()


def _clean_url(url):
    return url.rstrip(".,;:!?)>]'\"")


def _read_attachment(part):
    try:
        data = part.get_payload(decode=True)
    except Exception:
        data = None
    if data is None:
        data = b""
    filename = part.get_filename() or "(unnamed)"
    return AttachmentInfo(
        filename=str(filename),
        content_type=part.get_content_type(),
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        data=data,
    )


def _looks_like_headers(message):
    keys = {key.lower() for key in message.keys()}
    return len(keys & HEADER_NAMES) > 0


def parse_email(raw):
    """Parse a full .eml, raw source with headers, or a plain pasted body."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")

    message = message_from_bytes(raw, policy=policy.default)
    parsed = ParsedEmail()

    if not _looks_like_headers(message):
        text = raw.decode("utf-8", errors="replace")
        parsed.body_text = text.strip()
        parsed.has_headers = False
        parsed.links = _links_from_plain_text(parsed.body_text, [])
        return parsed

    parsed.has_headers = True
    parsed.subject = str(message.get("Subject", "") or "")
    parsed.from_name, parsed.from_addr = _single_address(message.get("From"))
    _, parsed.reply_to_addr = _single_address(message.get("Reply-To"))
    _, parsed.return_path_addr = _single_address(message.get("Return-Path"))
    parsed.to_addrs = [addr.lower() for _, addr in getaddresses([str(v) for v in message.get_all("To", [])]) if addr]
    parsed.auth_results = " ".join(str(v) for v in message.get_all("Authentication-Results", []))
    parsed.received_spf = " ".join(str(v) for v in message.get_all("Received-SPF", []))

    plain_text = ""
    html_text = ""
    for part in message.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        content_type = part.get_content_type()
        if disposition == "attachment" or (part.get_filename() and content_type not in ("text/plain", "text/html")):
            parsed.attachments.append(_read_attachment(part))
            continue
        if content_type == "text/plain" and not plain_text:
            plain_text = _safe_content(part)
        elif content_type == "text/html" and not parsed.body_html:
            parsed.body_html = _safe_content(part)
        elif part.get_filename():
            parsed.attachments.append(_read_attachment(part))

    html_links = []
    if parsed.body_html:
        html_text_value, html_links = html_to_text(parsed.body_html)
        if not plain_text:
            plain_text = html_text_value

    parsed.body_text = plain_text.strip()
    parsed.links = _links_from_plain_text(parsed.body_text, html_links)
    return parsed


def _safe_content(part):
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def _links_from_plain_text(text, html_links):
    links = list(html_links)
    seen = {link.href for link in links}
    for match in URL_PATTERN.findall(text or ""):
        url = _clean_url(match)
        if url not in seen:
            links.append(LinkInfo(href=url, anchor_text="", source="text"))
            seen.add(url)
    return links


def host_of(url):
    candidate = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", candidate):
        candidate = "http://" + candidate
    try:
        parsed = urlparse(candidate)
        host = parsed.hostname or ""
    except ValueError:
        host = ""
    return host.lower()
