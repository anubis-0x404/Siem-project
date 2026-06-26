import re
import json
import sys
import os
import time
from datetime import datetime, timedelta, timezone
from dateutil import parser as date_parser

try:
    from config.settings import AUTH_LOG_PATH
except ImportError:
    AUTH_LOG_PATH = "/var/log/remote/victim-auth.log"

TIMESTAMP_PREFIX = r"^([A-Z][a-z]{2}\s+\d+\s+[\d:]+|[\d\-T:+.]+)\s+\S+\s+sshd\[\d+\]:\s+"

PATTERNS = {
    "failed_password": re.compile(
        TIMESTAMP_PREFIX + r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
    ),
    "accepted_password": re.compile(
        TIMESTAMP_PREFIX + r"Accepted password for (\S+) from ([\d.]+) port (\d+)"
    ),
    "invalid_user": re.compile(
        TIMESTAMP_PREFIX + r"Invalid user (\S+) from ([\d.]+) port (\d+)"
    ),
    "pam_auth_failure": re.compile(
        TIMESTAMP_PREFIX + r"pam_unix\(sshd:auth\): authentication failure;.*rhost=(\S+)"
    ),
    "pam_excessive_failures": re.compile(
        TIMESTAMP_PREFIX + r"PAM \d+ more authentication failures;.*rhost=(\S+)"
    )
}

def normalize_timestamp(raw_time: str) -> str:
    try:
        raw_time = raw_time.strip()
        # Nếu log dùng định dạng ISO (Bắt đầu bằng số năm)
        if raw_time[0].isdigit():
            dt = date_parser.parse(raw_time)
        else:
            # Nếu log dạng truyền thống (Jun 25 09:25:26)
            current_year = datetime.now().year
            full_time = f"{raw_time} {current_year}"
            dt = date_parser.parse(full_time)

        if dt > datetime.now() + timedelta(days=7):
            dt = dt.replace(year=datetime.now().year - 1)
            
        return dt.strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

def parse_line(line: str) -> dict | None:
    original = line               
    line = line.strip()

    if not line:
        return None
        
    for event_type, pattern in PATTERNS.items():
        match = pattern.search(line)
        if match:
            raw_time = match.group(1)
            
            # Tách dữ liệu linh hoạt theo từng loại log sinh ra
            if event_type in ["failed_password", "accepted_password", "invalid_user"]:
                username = match.group(2)
                src_ip   = match.group(3)
                src_port = int(match.group(4))
            else:
                # Đối với log dạng PAM (Chỉ có thông tin IP nguồn, không kèm Port hệ thống)
                username = "unknown"
                src_ip   = match.group(2)
                src_port = 0 

            outcome = "success" if event_type == "accepted_password" else "failure"
            return {
                "event_type":  event_type,
                "timestamp":   normalize_timestamp(raw_time),
                "src_ip":      src_ip,
                "src_port":    src_port,
                "username":    username,
                "outcome":     outcome,
                "raw_log":     original.rstrip("\n"),
                "line_number": 0,
            }
    return None

_file_offsets: dict = {}
_line_counters: dict = {}

def parse_auth_log_incremental(filepath: str) -> list[dict]:
    results = []
    try:
        current_size = os.path.getsize(filepath)
        last_offset = _file_offsets.get(filepath, 0)
        current_line = _line_counters.get(filepath, 0)
        
        if current_size < last_offset:
            last_offset = 0
            current_line = 0

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(last_offset)
            for line in f:
                current_line += 1
                parsed = parse_line(line)
                if parsed:
                    parsed["line_number"] = current_line
                    results.append(parsed)
            
            _file_offsets[filepath] = f.tell()
            _line_counters[filepath] = current_line

    except FileNotFoundError:
        print(f"[ERROR] Không tìm thấy file log tại đường dẫn: {filepath}")
    except PermissionError:
        print(f"[ERROR] Quyền truy cập bị từ chối (Hãy chạy với sudo): {filepath}")

    return results

if __name__ == "__main__":
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    log_path = sys.argv[1] if len(sys.argv) > 1 else AUTH_LOG_PATH

    print(f"[*] [SIEM PARSER] Giám sát real-time file: {log_path}")
    print("[*] Nhấn Ctrl+C để dừng bộ Parser.")
    print("-" * 60)

    try:
        while True:
            events = parse_auth_log_incremental(log_path)
            if events:
                print(f"[+] Phát hiện {len(events)} sự kiện cấu trúc mới:")
                for event in events:
                    print(json.dumps(event, indent=2, ensure_ascii=False))
                    print("." * 40)
            time.sleep(1) # Quét mỗi giây một lần để đảm bảo tính real-time cao
    except KeyboardInterrupt:
        print("\n[-] Đã dừng tiến trình Auth Parser.")