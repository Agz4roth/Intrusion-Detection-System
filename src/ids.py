import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from colorama import init
init(autoreset=True)

import yaml
import queue
import threading
import platform

from threat_detector import ThreatDetector
from network_monitor import NetworkMonitor
from log_analyzer import LogAnalyzer
from alert_system import AlertSystem
from database_handler import Database
from notifier import Notifier

def detect_log_path():
    os_name = platform.system().lower()
    if "windows" in os_name:
        return "logs/test.log"
    elif "linux" in os_name:
        return "/var/log/auth.log"
    elif "darwin" in os_name:
        return "/var/log/system.log"
    else:
        return "logs/test.log"

CONFIG_PATH = "config/config.yaml"

def load_config(path=CONFIG_PATH):
    with open(path, "r") as f:
        return yaml.safe_load(f)

def main():
    cfg = load_config()
    cfg["logs"]["files"] = [detect_log_path()]
    print(f"[INFO] Selected log path: {cfg['logs']['files'][0]}")

    event_q = queue.Queue(maxsize=10000)
    rules_path = cfg["threats"]["rules_file"]

    db = Database(cfg["database"]["path"])
    db.init()

    alerts = AlertSystem(cfg["notifier"], silent=True)


    notifier = Notifier(
        telegram_token=cfg["notifier"].get("telegram_token"),
        telegram_chat_id=cfg["notifier"].get("telegram_chat_id"),
        email_config=cfg["notifier"].get("email_config"),
        webhook_url=cfg["notifier"].get("webhook_url"),
        debug_mode=False
    )

    # ThreatDetector
    detector = ThreatDetector(cfg, rules_path, db, alerts, notifier, debug_mode=False, silent=False)

    threads = []
    mode = cfg["app"]["mode"]

    if mode in ("logs", "both"):
        log_worker = LogAnalyzer(cfg["logs"]["files"], event_q, debug_mode=False)
        t_log = threading.Thread(target=log_worker.run, daemon=True)
        threads.append(t_log)

    if mode in ("network", "both"):
        net_worker = NetworkMonitor(cfg["network"]["interface"], event_q, debug_mode=False)
        t_net = threading.Thread(target=net_worker.run, daemon=True)
        threads.append(t_net)

    for t in threads:
        t.start()

    try:
        while True:
            try:
                event = event_q.get(timeout=1.0)
                detector.process_event(event)
            except queue.Empty:
                pass
    except KeyboardInterrupt:
        print("[IDS] Shutting down...")
    finally:
        db.close()

if __name__ == "__main__":
    main()
