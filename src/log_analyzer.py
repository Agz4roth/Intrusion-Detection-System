import time
import os
from charset_normalizer import from_path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class LogEventHandler(FileSystemEventHandler):
    def __init__(self, path, event_q, debug_mode=False):
        self.path = os.path.abspath(path)
        self.event_q = event_q
        self.last_size = 0
        self.debug_mode = debug_mode
        self.encoding = self._detect_encoding()

    def _debug(self, msg):
        if self.debug_mode:
            print(f"[DEBUG] {msg}")

    def _detect_encoding(self):
        try:
            result = from_path(self.path).best()
            enc = result.encoding
            self._debug(f"Detected encoding for {self.path}: {enc}")
            return enc
        except Exception as e:
            print(f"[LOG] Encoding detection failed: {e}")
            return "utf-8"

    def process_file(self):
        try:
            with open(self.path, "r", encoding=self.encoding, errors="ignore") as f:
                f.seek(self.last_size)
                new_lines = f.readlines()
                self.last_size = f.tell()

                for line in new_lines:
                    clean = line.strip()
                    if not clean or len(clean) < 5:
                        continue
                    self._debug(f"New log line detected: {clean}")
                    event = {
                        "type": "log",
                        "ts": time.time(),
                        "src": self.path,
                        "message": clean
                    }
                    self.event_q.put(event)
                    self._debug(f"Event queued: {event}")
        except Exception as e:
            print(f"[LOG] Error reading {self.path}: {e}")

    def on_modified(self, event):
        if os.path.abspath(event.src_path) == self.path:
            self._debug(f"on_modified triggered for {event.src_path}")
            self.process_file()

    def on_created(self, event):
        if os.path.abspath(event.src_path) == self.path:
            self._debug(f"on_created triggered for {event.src_path}")
            self.last_size = 0
            self.encoding = self._detect_encoding()
            self.process_file()

class LogAnalyzer:
    def __init__(self, log_paths, event_q, debug_mode=False):
        self.log_paths = [os.path.abspath(p) for p in log_paths]
        self.event_q = event_q
        self.observer = Observer()
        self.debug_mode = debug_mode

    def _debug(self, msg):
        if self.debug_mode:
            print(f"[DEBUG] {msg}")

    def run(self):
        print(f"[INFO] Log monitoring started on {self.log_paths} follow=True")
        for path in self.log_paths:
            if not os.path.exists(path):
                print(f"[LOG] File not found: {path}")
                continue

            handler = LogEventHandler(path, self.event_q, debug_mode=self.debug_mode)
            watch_dir = os.path.dirname(path) or "."
            self._debug(f"Watching directory: {watch_dir}")
            self.observer.schedule(handler, path=watch_dir, recursive=False)

        self.observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()
