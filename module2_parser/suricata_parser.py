import json
import sys
import os
from datetime import datetime, timedelta
from config.settings import SEVERITY_MAP, EVE_JSON_PATH
from dateutil import parser as date_parser
def normalize_timestamp(raw_time: str) -> str:
    try:
        raw_time = raw_time.strip()
        if raw_time[0].isdigit():
            dt = date_parser.parse(raw_time)
        else:
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
    line     = line.strip()

    if not line:
        return None

    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        print(f"[WARN] Dòng JSON không hợp lệ: {line[:60]}...")
        return None

    if event.get("event_type") != "alert":
        return None

    alert_info = event.get("alert")
    if not alert_info:
        print(f"[WARN] Event alert thiếu field 'alert': {line[:60]}...")
        return None

    severity_num  = alert_info.get("severity", 4)
    severity_name = SEVERITY_MAP.get(severity_num, "LOW")

    return {
        "event_type":  "suricata_alert",
        "timestamp":   normalize_timestamp(event.get("timestamp", "")),
        "src_ip":      event.get("src_ip",   ""),
        "src_port":    event.get("src_port",  0),
        "dest_ip":     event.get("dest_ip",  ""),
        "dest_port":   event.get("dest_port", 0),
        "proto":       event.get("proto",    ""),
        "signature":   alert_info.get("signature", ""),
        "severity":    severity_name,
        "category":    alert_info.get("category",  ""),
        "outcome":     "unknown",             
        "raw_log":     original.rstrip("\n"), 
        "line_number": 0,                     
    }

def parse_eve_json(filepath: str) -> list[dict]:
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

_file_offsets: dict = {}

def parse_auth_log_incremental(filepath: str) -> list[dict]:
    results = []
    try:
        current_size = os.path.getsize(filepath)
        last_offset  = _file_offsets.get(filepath, 0)
        if current_size < last_offset:
            last_offset = 0

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(last_offset)
            for line in f:
                parsed = parse_line(line)
                if parsed:
                    results.append(parsed)
            _file_offsets[filepath] = f.tell()

    except FileNotFoundError:
        print(f"[ERROR] Không tìm thấy file: {filepath}")
    except PermissionError:
        print(f"[ERROR] Không có quyền đọc file: {filepath}")

if __name__ == "__main__":
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    log_path = sys.argv[1] if len(sys.argv) > 1 else EVE_JSON_PATH
    print(f"[*] Đang parse file: {log_path}")
    events = parse_eve_json(log_path)
    print(f"[+] Tìm thấy {len(events)} Suricata alert\n")

    for event in events:
        print(json.dumps(event, indent=2, ensure_ascii=False))
        print("-" * 50)