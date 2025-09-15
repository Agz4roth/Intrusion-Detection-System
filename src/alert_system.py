import smtplib
from email.mime.text import MIMEText

class AlertSystem:
    def __init__(self, cfg, silent=False):
        self.cfg = cfg or {}
        self.silent = silent
        self.console = bool(self.cfg.get("console", False))
        self.email = self.cfg.get("email", {}) or {}
        self.email_enabled = bool(self.email.get("enabled", False))


    def _console(self, message, severity):
        print(f"[ALERT - {severity.upper()}] {message}")

    def _email(self, message, severity):
        try:
            msg = MIMEText(message)
            msg["Subject"] = f"[IDS] {severity.upper()} alert"
            msg["From"] = self.email["from_addr"]
            msg["To"] = ", ".join(self.email["to_addrs"])

            server = smtplib.SMTP(self.email["smtp_host"], self.email["smtp_port"], timeout=10)
            if self.email.get("use_tls", True):
                server.starttls()
            server.login(self.email["username"], self.email["password"])
            server.sendmail(self.email["from_addr"], self.email["to_addrs"], msg.as_string())
            server.quit()
        except Exception as e:
            print(f"[ALERT] Email send failed: {e}")

    def dispatch(self, message, severity="medium"):
        if self.console:
            self._console(message, severity)
        if self.email_enabled:
            self._email(message, severity)
