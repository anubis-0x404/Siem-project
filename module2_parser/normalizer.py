import json
import sys
import os
from datetime import datetime
from config.settings import AUTH_LOG_PATH, EVE_JSON_PATH
from module2_parser.auth_parser     import parse_auth_log
from module2_parser.suricata_parser import parse_eve_json

EVENT_MAP = {
    "failed_password": {
        "category": "authentication",
        "severity": "MEDIUM",
        "tags":     ["ssh", "auth", "brute-force"],
    },
    "accepted_password": {
        "category": "authentication",
        "severity": "INFO",
        "tags":     ["ssh", "auth", "login-success"],
    },
    "invalid_user": {
        "category": "authentication",
        "severity": "MEDIUM",
        "tags":     ["ssh", "auth", "invalid-user"],
    },
    "suricata_alert": {
        "category": "network",
        "tags":     ["suricata", "ids-alert"],
    },
}

def normalize_auth_event(raw: dict) -> dict:
    event_type = raw.get("event_type", "")
    meta       = EVENT_MAP.get(event_type, {
        "category": "authentication",
        "severity": "LOW",
        "tags":     ["ssh"],
    })

    return {
        # Metadata
        "@timestamp":           raw.get("timestamp",
                                datetime.now().strftime("%Y-%m-%dT%H:%M:%S")),
        "event.kind":           "event",
        "event.category":       meta["category"],
        "event.outcome":        raw.get("outcome", "failure"),
        "event.severity_label": meta["severity"],
        "event.type":           event_type,

        # Mạng
        "source.ip":            raw.get("src_ip",   ""),
        "source.port":          raw.get("src_port",  0),
        "destination.ip":       "",
        "destination.port":     22,
        "network.protocol":     "ssh",

        # Người dùng
        "user.name":            raw.get("username", ""),

        # Rule
        "rule.name":            "",

        # Metadata hệ thống
        "log.original":         raw.get("raw_log",      ""),
        "tags":                 meta["tags"],
        "data_source":          "auth_log",
        "line_number":          raw.get("line_number",   0),
    }

def normalize_suricata_event(raw: dict) -> dict:
    meta = EVENT_MAP.get("suricata_alert", {})

    return {
        # Metadata
        "@timestamp":           raw.get("timestamp",
                                datetime.now().strftime("%Y-%m-%dT%H:%M:%S")),
        "event.kind":           "alert",
        "event.category":       meta["category"],
        "event.outcome":        "unknown",            
        "event.severity_label": raw.get("severity", "MEDIUM"),  
        "event.type":           "suricata_alert",

        # Mạng
        "source.ip":            raw.get("src_ip",    ""),
        "source.port":          raw.get("src_port",   0),
        "destination.ip":       raw.get("dest_ip",   ""),
        "destination.port":     raw.get("dest_port",  0),
        "network.protocol":     raw.get("proto",     "").lower(),

        # Người dùng (không có với suricata)
        "user.name":            "",

        # Rule
        "rule.name":            raw.get("signature", ""),
        "rule.category":        raw.get("category",  ""),

        # Metadata hệ thống
        "log.original":         raw.get("raw_log",      ""),
        "tags":                 meta["tags"],
        "data_source":          "suricata",
        "line_number":          raw.get("line_number",   0),
    }

def normalize(raw: dict) -> dict | None:
    if not raw:
        return None
    event_type = raw.get("event_type", "")
    if event_type in ("failed_password", "accepted_password", "invalid_user"):
        return normalize_auth_event(raw)

    elif event_type == "suricata_alert":
        return normalize_suricata_event(raw)
    else:
        return None

if __name__ == "__main__":
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    print("=" * 60)
    print("NORMALIZER — Auth log")
    print("=" * 60)
    auth_events = parse_auth_log(AUTH_LOG_PATH)
    for raw in auth_events:
        normalized = normalize(raw)
        if normalized:
            print(json.dumps(normalized, indent=2, ensure_ascii=False))
            print("-" * 50)

    print("=" * 60)
    print("NORMALIZER — Suricata eve.json")
    print("=" * 60)
    suricata_events = parse_eve_json(EVE_JSON_PATH)
    for raw in suricata_events:
        normalized = normalize(raw)
        if normalized:
            print(json.dumps(normalized, indent=2, ensure_ascii=False))
            print("-" * 50)
