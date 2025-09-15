import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class Notifier:
    def __init__(self, telegram_token=None, telegram_chat_id=None, email_config=None, webhook_url=None, debug_mode=False):
        self.telegram_token = telegram_token
        self.telegram_chat_id = int(telegram_chat_id) if telegram_chat_id else None
        self.email_config = email_config or {}
        self.webhook_url = webhook_url if webhook_url else None
        self.debug_mode = debug_mode

    def notify(self, message: str, severity: str):
        if severity.lower() not in ["high", "medium"]:
            return

        if self.telegram_token and self.telegram_chat_id:
            self._send_telegram(message)

        if self.email_config.get("sender") and self.email_config.get("recipient"):
            self._send_email(message)

        if self.webhook_url and self.webhook_url.strip():
            self._send_webhook(message)

    def _send_telegram(self, message: str):
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": message,
            "parse_mode": "HTML"
        }
        try:
            response = requests.post(url, json=payload, timeout=5)
            if self.debug_mode:
                print(f"[Notifier] Telegram status: {response.status_code}")
        except Exception as e:
            print(f"[Notifier] Telegram error: {e}")


    def _send_email(self, message: str):
        try:
            smtp_host = self.email_config.get("smtp_server", "")
            port = self.email_config.get("port", 587)
            sender = self.email_config.get("sender")
            password = self.email_config.get("password")
            recipient = self.email_config.get("recipient")

            if not all([smtp_host, sender, password, recipient]):
                print("[Notifier] Email config incomplete, skipping email.")
                return

            msg = MIMEMultipart("alternative")
            msg["Subject"] = "🚨 IDS Alert: HIGH Severity"
            msg["From"] = sender
            msg["To"] = recipient

            html_body = f"<html><body><pre>{message}</pre></body></html>"
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(smtp_host, port) as server:
                server.starttls()
                server.login(sender, password)
                server.sendmail(sender, recipient, msg.as_string())

            print("[Notifier] Email sent successfully.")
        except Exception as e:
            print(f"[Notifier] Email error: {e}")

    def _send_webhook(self, message: str):
        payload = {"alert": message}
        try:
            print("[Notifier] Sending Webhook message...")
            response = requests.post(self.webhook_url, json=payload, timeout=5)
            print(f"[Notifier] Webhook response: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"[Notifier] Webhook error: {e}")
