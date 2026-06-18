import json
import sys
import os
from datetime import datetime

SEVERITY_MAP = {
    1: "CRITICAL",
    2: "HIGH",
    3: "MEDIUM",
    4: "LOW",
}

def normalize_timestamp(raw_time: str) -> str:
    try:
        return raw_time[:19]
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

if __name__ == "__main__":
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config.settings import EVE_JSON_PATH
    log_path = sys.argv[1] if len(sys.argv) > 1 else EVE_JSON_PATH
    print(f"[*] Đang parse file: {log_path}")
    events = parse_eve_json(log_path)
    print(f"[+] Tìm thấy {len(events)} Suricata alert\n")

    for event in events:
        print(json.dumps(event, indent=2, ensure_ascii=False))
        print("-" * 50)