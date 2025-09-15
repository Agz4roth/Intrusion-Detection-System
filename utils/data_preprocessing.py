import re

_ws = re.compile(r"\s+")
def normalize_log_line(line: str) -> str:
    # Lowercase + collapse whitespace to help rule matching
    return _ws.sub(" ", line.strip().lower())
