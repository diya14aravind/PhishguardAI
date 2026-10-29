import time

from phishguard.agents.attachment import AttachmentAgent
from phishguard.agents.content import ContentAgent
from phishguard.agents.sender import SenderAgent
from phishguard.agents.social import SocialEngineeringAgent
from phishguard.agents.url_agent import URLAgent
from phishguard.fusion import fuse
from phishguard.parser import parse_email
from phishguard.threat_intel import build_intel


class PhishGuardPipeline:
    def __init__(self):
        self.content = ContentAgent()
        self.url = URLAgent()
        self.sender = SenderAgent()
        self.attachment = AttachmentAgent()
        self.social = SocialEngineeringAgent()

    def analyze_raw(self, raw):
        """raw: bytes or str of an .eml file, full source, or a plain pasted body."""
        return self.analyze(parse_email(raw))

    def analyze_fields(self, subject="", sender="", body="", headers=""):
        """Build an email from separate form fields and analyse it."""
        lines = []
        if headers.strip():
            lines.append(headers.strip())
        if sender.strip():
            lines.append("From: " + sender.strip())
        if subject.strip():
            lines.append("Subject: " + subject.strip())
        if not lines:
            return self.analyze_raw(body)
        raw = "\n".join(lines) + "\n\n" + body
        return self.analyze_raw(raw)

    def analyze(self, email):
        started = time.time()
        results = {
            "content": self.content.analyze(email),
            "url": self.url.analyze(email),
            "sender": self.sender.analyze(email),
            "attachment": self.attachment.analyze(email),
            "social": self.social.analyze(email),
        }
        fusion = fuse(results, email)
        intel = build_intel(email, results, fusion)
        return {
            "email": {
                "subject": email.subject,
                "from": email.from_addr,
                "display_name": email.from_name,
                "reply_to": email.reply_to_addr,
                "has_headers": email.has_headers,
                "link_count": len(email.links),
                "attachment_count": len(email.attachments),
            },
            "verdict": fusion["verdict"],
            "fusion": fusion,
            "agents": {name: result.to_dict() for name, result in results.items()},
            "threat_intel": intel,
            "elapsed_ms": round(1000 * (time.time() - started)),
        }
