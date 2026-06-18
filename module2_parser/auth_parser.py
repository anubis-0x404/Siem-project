import re
import json
import sys
import os

from datetime import datetime, timedelta
from dateutil import parser as date_parser

PATTERNS = {
    "failed_password": re.compile(
        r"(\w{3}\s+\d+\s[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
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
        full_time    = f"{raw_time} {current_year}"
        dt           = date_parser.parse(full_time)

        # Guard: timestamp không hợp lệ nếu nằm quá xa trong tương lai
        if dt > datetime.now() + timedelta(days=7):
            dt = dt.replace(year=current_year - 1)
        return dt.strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

def parse_line(line: str) -> dict | None:
    original = line              
    line     = line.strip()

    if not line:
        return None
    for event_type, pattern in PATTERNS.items():
        match = pattern.search(line)
        if match:
            raw_time  = match.group(1)
            username  = match.group(2)
            src_ip    = match.group(3)
            src_port  = int(match.group(4))

            outcome = "success" if event_type == "accepted_password" else "failure"
            return {
                "event_type":  event_type,
                "timestamp":   normalize_timestamp(raw_time),
                "src_ip":      src_ip,
                "src_port":    src_port,
                "username":    username,
                "outcome":     outcome,
                "raw_log":     original.rstrip("\n"),
                "line_number": 0,   # ← FIX #2: default; parse_auth_log sẽ ghi đè
            }

    return None

def parse_auth_log(filepath: str) -> list[dict]:
    results = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, start=1):
                parsed = parse_line(line)
                if parsed:
                    parsed["line_number"] = line_num   # ghi đè default 0
                    results.append(parsed)

    except FileNotFoundError:
        print(f"[ERROR] Không tìm thấy file: {filepath}")
    except PermissionError:
        print(f"[ERROR] Không có quyền đọc file: {filepath}")
    return results

if __name__ == "__main__":
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    log_path = sys.argv[1] if len(sys.argv) > 1 else "logs/sample/auth.log"

    print(f"[*] Đang parse file: {log_path}")
    events = parse_auth_log(log_path)
    print(f"[+] Tìm thấy {len(events)} sự kiện SSH\n")

    for event in events:
        print(json.dumps(event, indent=2, ensure_ascii=False))
        print("-" * 50)