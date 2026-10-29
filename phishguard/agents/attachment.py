import io
import re
import zipfile

from phishguard.agents.base import AgentResult, noisy_or

EXECUTABLE_EXT = {"exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe", "wsf",
                  "wsh", "ps1", "jar", "msi", "lnk", "hta", "cpl", "reg", "dll"}
DISK_IMAGE_EXT = {"iso", "img", "vhd", "vhdx"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "cab", "ace"}
HTML_EXT = {"html", "htm", "shtml", "xhtml", "svg"}
OFFICE_EXT = {"doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf"}
SAFE_EXT = {"pdf", "txt", "png", "jpg", "jpeg", "gif", "csv", "ics", "bmp"}

DOUBLE_EXTENSION = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|csv)\s*\.(exe|scr|js|vbs|bat|cmd|com|lnk|jar|hta|ps1|msi)$",
    re.IGNORECASE)

MAX_SCAN_BYTES = 2 * 1024 * 1024


def _extension(filename):
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1].lower().strip()


class AttachmentAgent:
    name = "attachment"

    def analyze(self, email):
        result = AgentResult(name=self.name)
        if not email.attachments:
            result.findings.append("No attachments.")
            return result

        reports = []
        for attachment in email.attachments:
            reports.append(self._analyze_attachment(attachment, email.body_text))

        scores = [report["score"] for report in reports]
        risky_count = len([s for s in scores if s >= 0.4])
        result.score = min(1.0, max(scores) + 0.05 * max(0, risky_count - 1))
        for report in reports:
            if report["score"] >= 0.3:
                for finding in report["findings"]:
                    result.findings.append(report["filename"] + ": " + finding)
            for code in report["signals"]:
                if code not in result.signals:
                    result.signals.append(code)
        if not result.findings:
            result.findings.append(str(len(reports)) + " attachment(s) checked, nothing risky found.")
        result.details["attachments"] = reports
        return result

    def _analyze_attachment(self, attachment, body_text):
        findings = []
        signals = []
        weights = []

        def flag(code, weight, text):
            signals.append(code)
            weights.append(weight)
            findings.append(text)

        filename = attachment.filename
        ext = _extension(filename)
        data = attachment.data[:MAX_SCAN_BYTES]

        if DOUBLE_EXTENSION.search(filename):
            flag("attach_double_extension", 0.90, "Double extension hides an executable file type.")
        elif ext in EXECUTABLE_EXT:
            flag("attach_executable", 0.85, "File type '." + ext + "' can run code on your computer.")
        elif ext in DISK_IMAGE_EXT:
            flag("attach_disk_image", 0.60, "Disk image attachments are often used to deliver malware.")
        elif ext in MACRO_EXT:
            flag("attach_macro_document", 0.60, "Macro-enabled Office document.")
        elif ext in HTML_EXT:
            flag("attach_html", 0.50, "HTML attachments are often used to host fake login pages.")
        elif ext in ARCHIVE_EXT:
            flag("attach_archive", 0.25, "Archive files can hide malicious content from scanners.")
        elif ext not in OFFICE_EXT and ext not in SAFE_EXT:
            flag("attach_unknown_type", 0.10, "Unusual file type.")

        self._check_magic_bytes(data, ext, flag)
        self._check_pdf(data, ext, flag)
        self._check_office(data, ext, flag)
        self._check_zip(data, ext, body_text, flag)

        return {
            "filename": filename,
            "content_type": attachment.content_type,
            "size": attachment.size,
            "sha256": attachment.sha256,
            "score": round(noisy_or(weights), 3),
            "findings": findings,
            "signals": signals,
        }

    def _check_magic_bytes(self, data, ext, flag):
        if data[:2] == b"MZ" and ext not in EXECUTABLE_EXT:
            flag("attach_disguised_executable", 0.95, "File is a Windows executable disguised as '." + ext + "'.")
        if data[:4] == b"\x7fELF" and ext not in EXECUTABLE_EXT:
            flag("attach_disguised_executable", 0.90, "File is a Linux executable disguised as '." + ext + "'.")
        if data[:4] == b"%PDF" and ext not in ("pdf", ""):
            flag("attach_type_mismatch", 0.30, "File content is a PDF but the name says '." + ext + "'.")

    def _check_pdf(self, data, ext, flag):
        if data[:4] != b"%PDF":
            return
        active_markers = [b"/JavaScript", b"/JS", b"/Launch", b"/OpenAction", b"/EmbeddedFile"]
        found = [marker.decode() for marker in active_markers if marker in data]
        if found:
            flag("attach_pdf_active_content", 0.55, "PDF contains active content: " + ", ".join(found) + ".")

    def _check_office(self, data, ext, flag):
        if data[:8] == bytes.fromhex("D0CF11E0A1B11AE1") and ext in ("doc", "xls", "ppt"):
            if b"VBA" in data or b"Macros" in data:
                flag("attach_macro_document", 0.55, "Legacy Office file appears to contain macros.")

    def _check_zip(self, data, ext, body_text, flag):
        if data[:4] != b"PK\x03\x04":
            return
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
            infos = archive.infolist()
        except (zipfile.BadZipFile, RuntimeError):
            return

        names = [info.filename.lower() for info in infos]
        if any(name.endswith("vbaproject.bin") for name in names):
            flag("attach_macro_document", 0.80, "Document contains an embedded VBA macro project.")

        if ext in OFFICE_EXT:
            return
        if ext in ("pdf", "png", "jpg", "jpeg", "txt", "gif"):
            flag("attach_type_mismatch", 0.50, "File is a ZIP archive but the name says '." + ext + "'.")
            return

        inner_executables = [n for n in names if _extension(n) in EXECUTABLE_EXT]
        if inner_executables:
            flag("attach_archive_executable", 0.85, "Archive contains an executable: " + inner_executables[0] + ".")
        encrypted = any(info.flag_bits & 0x1 for info in infos)
        if encrypted:
            flag("attach_encrypted_archive", 0.40, "Archive is password protected, which hides its contents from scanners.")
            if re.search(r"password", body_text or "", re.IGNORECASE):
                flag("attach_password_in_body", 0.30, "The email body gives the archive password.")
