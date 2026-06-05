import re
import json
from datetime import datetime
from dateutil import parser as date_parser

# Pattern cho từng loại dòng log
PATTERNS = {
    "failed_password": re.compile(
        r"(\w{3}\s+\d+\s[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Failed password for (\S+) from ([\d.]+) port (\d+)"
    ),
    "accepted_password": re.compile(
        r"(\w{3}\s+\d+\s[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Accepted password for (\S+) from ([\d.]+) port (\d+)"
    ),
    "invalid_user": re.compile(
        r"(\w{3}\s+\d+\s[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Invalid user (\S+) from ([\d.]+) port (\d+)"
    ),
}

def normalize_timestamp(raw_time: str) -> str:
    
    try:
        current_year = datetime.now().year
        full_time = f"{raw_time} {current_year}"
        dt = date_parser.parse(full_time)
        return dt.strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

# Hàm parse từng dòng log
def parse_line(line: str) -> dict | None:

    line = line.strip()
    if not line:
        return None

    # Thử từng pattern
    for event_type, pattern in PATTERNS.items():
        match = pattern.search(line)
        if match:
            raw_time = match.group(1)
            username = match.group(2)
            src_ip   = match.group(3)
            src_port = int(match.group(4))

            if event_type == "accepted_password":
                outcome = "success"
            else:
                outcome = "failure"

            return {
                "event_type":  event_type,
                "timestamp":   normalize_timestamp(raw_time),
                "src_ip":      src_ip,
                "src_port":    src_port,
                "username":    username,
                "outcome":     outcome,
                "raw_log":     line,
            }

    return None

def parse_auth_log(filepath: str) -> list[dict]:
  
    results = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, start=1):
                parsed = parse_line(line)
                if parsed:
                    parsed["line_number"] = line_num
                    results.append(parsed)

    except FileNotFoundError:
        print(f"[ERROR] Không tìm thấy file: {filepath}")
    except PermissionError:
        print(f"[ERROR] Không có quyền đọc file: {filepath}")

    return results

if __name__ == "__main__":
    import sys
    import os

    # Thêm thư mục gốc vào sys.path để import settings
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config.settings import AUTH_LOG_PATH

    # Ưu tiên 1: đường dẫn truyền từ terminal
    # Ưu tiên 2: đường dẫn từ settings.py
    # Ví dụ chạy: python3 auth_parser.py /var/log/auth.log
    log_path = sys.argv[1] if len(sys.argv) > 1 else AUTH_LOG_PATH

    print(f"[*] Đang parse file: {log_path}")
    events = parse_auth_log(log_path)

    print(f"[+] Tìm thấy {len(events)} sự kiện SSH\n")
    for event in events:
        print(json.dumps(event, indent=2, ensure_ascii=False))
        print("-" * 50)