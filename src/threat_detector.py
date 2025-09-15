import json
import re
import time
from typing import Dict, Any
from rich.console import Console
from ml_engine import LogClassifier
from rich.table import Table
from ip_reputation import IPReputationChecker
from vt_checker import VirusTotalChecker

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}
console = Console()

class ThreatDetector:
    def __init__(self, cfg: Dict[str, Any], rules_path: str, db, alerts, notifier=None, debug_mode=False, silent=False):
        self.cfg = cfg
        self.db = db
        self.alerts = alerts
        self.notifier = notifier
        self.debug_mode = debug_mode
        self.silent = silent
        self.threshold_rank = SEVERITY_RANK.get(cfg["threats"].get("severity_threshold", "low"), 1)
        self.rules = self._load_rules(rules_path)
        self.seen_events = set()
        self.counters = {}

        self.ip_checker = IPReputationChecker(
            api_key=cfg["threats"].get("abuseipdb_api_key", ""),
            threshold=cfg["threats"].get("ip_reputation_threshold", 50),
            debug_mode=self.debug_mode
        )

        self.vt_checker = VirusTotalChecker(
            api_key=cfg["threats"].get("virustotal_api_key", ""),
            debug_mode=self.debug_mode
        )

    def _debug(self, msg: str):
        if self.debug_mode:
            print(f"[DEBUG] {msg}")

    def _load_rules(self, path: str):
        with open(path, "r", encoding="utf-8") as f:
            rules = json.load(f)
        compiled = []
        for rule in rules:
            try:
                rx = re.compile(rule["pattern"])
            except re.error:
                rx = re.compile(re.escape(rule["pattern"]))
            compiled.append({**rule, "rx": rx})
        self._debug(f"Loaded rules: {[r['id'] for r in compiled]}")
        return compiled

    def _passes_threshold(self, severity: str) -> bool:
        return SEVERITY_RANK.get(severity.lower(), 1) >= self.threshold_rank

    def _key_for_event(self, rule_id: str, event: Dict[str, Any]) -> str:
        if event["type"] == "log":
            return f"log:{rule_id}:{event.get('message', '')[:100]}"
        if event["type"] == "network":
            return f"net:{rule_id}:{event.get('src_ip', '')}"
        return f"evt:{rule_id}"

    def _rate_limit(self, rule_id: str, window: int = 30, threshold: int = 5) -> bool:
        now = time.time()
        count, first_ts = self.counters.get(rule_id, (0, now))
        if now - first_ts > window:
            count, first_ts = 0, now
        count += 1
        self.counters[rule_id] = (count, first_ts)
        return count >= threshold

    def _record_and_alert(self, rule: Dict[str, Any], details: Dict[str, Any]):
        if not self._passes_threshold(rule["severity"]):
            return

        # Check for IP reputation using AbuseIPDB and VirusTotal
        ip_match = re.search(r"(\d{1,3}\.){3}\d{1,3}", details.get("line", ""))
        if ip_match:
            ip = ip_match.group(0)
            if self.ip_checker.is_malicious(ip):
                rule["severity"] = "high"
                rule["description"] += " | Flagged by AbuseIPDB"
            vt_score = self.vt_checker.check_ip(ip)
            if vt_score and vt_score > 5:
                rule["severity"] = "high"
                rule["description"] += " | Flagged by VirusTotal"

        # Compose and store the raw message
        message = f"{rule['id']}: {rule['description']} | {details}"
        self.db.insert_threat(rule["id"], rule["severity"], message)
        self.alerts.dispatch(message, severity=rule["severity"])

        # Store structured alert in database
        alert = {
            "id": rule["id"],
            "description": rule["description"],
            "severity": rule["severity"],
            "src_ip": details.get("src_ip"),
            "dst_ip": details.get("dst_ip"),
            "proto": details.get("proto"),
            "timestamp": details.get("timestamp", time.time()),
            "rep_score": details.get("rep_score", 0)
        }
        self.db.insert_alert(alert)

        # Initialize ML classifier
        classifier = LogClassifier()

        # Prepare notification if notifier is available
        if hasattr(self, "notifier") and self.notifier:
            if "src_ip" not in details or not details["src_ip"]:
                ip_match = re.search(r"(\d{1,3}\.){3}\d{1,3}", details.get("line", ""))
                if ip_match:
                    details["src_ip"] = ip_match.group(0)

            formatted = (
                f"🚨 <b>[{rule['severity'].upper()}]</b> <code>{rule['id']}</code>\n"
                f"📄 <b>Description:</b> {rule['description']}\n"
                f"📍 <b>Source IP:</b> {details.get('src_ip', 'N/A')}\n"
                f"🕒 <b>Timestamp:</b> {details.get('timestamp', time.time())}\n"
                f"📁 <b>Log Path:</b> {details.get('path', 'N/A')}\n"
                f"🔎 <b>Log Line:</b> {details.get('line', '')}"
            )

            # ML-based filtering before sending notification
            if classifier.predict(details["line"]) == "malicious":
                self.notifier.notify(formatted, rule["severity"])

        # Optional terminal output (if not in silent mode)
        if not self.silent:
            severity_display = {
                "high": "[red]HIGH[/red]",
                "medium": "[yellow]MEDIUM[/yellow]",
                "low": "[green]LOW[/green]"
            }.get(rule["severity"].lower(), rule["severity"])

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Rule ID", style="cyan", no_wrap=True)
            table.add_column("Severity")
            table.add_column("Description", style="white")
            table.add_row(rule["id"], severity_display, rule["description"])
            console.print(table)

    def _handle_log(self, event: Dict[str, Any]):
        line = event.get("message", "").strip()
        self._debug(f"Processing log line: {line}")
        for rule in self.rules:
            if rule.get("source") not in (None, "log"):
                continue
            if rule["rx"].search(line):
                event_key = self._key_for_event(rule["id"], event)
                if event_key in self.seen_events:
                    continue
                self.seen_events.add(event_key)

                should_alert = True
                if rule["id"] == "SSH_BRUTE_FORCE":
                    should_alert = self._rate_limit(rule["id"], window=60, threshold=5)
                if should_alert:
                    details = {"path": event.get("src"), "line": line[:200]}
                    self._record_and_alert(rule, details)

    def _handle_network(self, event: Dict[str, Any]):
        src_ip = event.get("src_ip")
        hint = event.get("info", {}).get("signature_hint")
        for rule in self.rules:
            if rule.get("source") not in (None, "network"):
                continue
            if hint and hint == rule["pattern"]:
                event_key = self._key_for_event(rule["id"], event)
                if event_key in self.seen_events:
                    continue
                self.seen_events.add(event_key)

                should_alert = self._rate_limit(rule["id"], window=10, threshold=1)
                if should_alert:
                    details = {
                        "src_ip": src_ip,
                        "dst_ip": event.get("dst_ip"),
                        "proto": event.get("proto"),
                        "rep_score": self.ip_checker.check_ip(src_ip)
                    }
                    self._record_and_alert(rule, details)

    def process_event(self, event: Dict[str, Any]):
        etype = event.get("type")
        if self.debug_mode:
            self._debug(f"Processing event type: {etype}")
        if etype == "log":
            self._handle_log(event)
        elif etype == "network":
            self._handle_network(event)