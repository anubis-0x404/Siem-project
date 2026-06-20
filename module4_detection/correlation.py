import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime
from elasticsearch import Elasticsearch
from config.settings import (
    ES_INDEX_PREFIX,
    CORRELATION_WINDOW,
    BRUTE_FORCE_THRESHOLD,
    PORT_SCAN_THRESHOLD,    
)
from module4_detection.rule_based import create_alert

correlation_state: dict = {}
STATE_TTL_MINUTES = 20
# Xoa state het han
def cleanup_expired_states(ttl_minutes: int = STATE_TTL_MINUTES) -> None:
    now = datetime.now()
    expired_ips = [
        ip for ip, data in correlation_state.items()
        if (now - data.get("updated_at", now)).total_seconds()
        > ttl_minutes * 60
    ]
    for ip in expired_ips:
        del correlation_state[ip]
        print(f"  [INFO] Xóa state hết hạn: {ip}")

#Lay ds IP dang hoat dong
def get_active_ips(es: Elasticsearch,
                   minutes: int = 15) -> list[str]:
    query = {
        "query": {
            "range": {
                "@timestamp": {"gte": f"now-{minutes}m"}
            }
        },
        "aggs": {
            "active_ips": {
                "terms": {
                    "field": "source.ip",
                    "size":  100          # Top 100 IP hoạt động nhiều nhất
                }
            }
        },
        "size": 0   
    }

    try:
        response = es.search(
            index=f"{ES_INDEX_PREFIX}-*",
            body=query
        )
        buckets = response["aggregations"]["active_ips"]["buckets"]
        return [b["key"] for b in buckets]
    except Exception as e:
        print(f"[ERROR] get_active_ips: {e}")
        return []
    
#B1: kiem tra Port Scan
def check_step_port_scan(es: Elasticsearch,
                          src_ip: str,
                          minutes: int) -> bool:
    # Điều kiện 1: Suricata đã cảnh báo có "SCAN" trong rule.name
    # (field đúng là rule.name — KHÔNG phải alert.signature như bản cũ)
    signature_query = {
        "query": {
            "bool": {
                "must": [
                    {"term":  {"source.ip": src_ip}},
                    {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}},
                ],
                "should": [
                    {"wildcard": {"rule.name": "*SCAN*"}},
                    {"wildcard": {"rule.name": "*Scan*"}},
                ],
                "minimum_should_match": 1
            }
        }
    }
    try:
        count = es.count(index=f"{ES_INDEX_PREFIX}-*", body=signature_query)["count"]
        if count > 0:
            return True
    except Exception:
        pass

    # Điều kiện 2 (fallback): đếm số cổng đích khác nhau — kích hoạt
    # khi Suricata không có rule nào chứa chữ "SCAN" trong tên
    port_query = {
        "query": {
            "bool": {
                "must": [
                    {"term":  {"source.ip": src_ip}},
                    {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}},
                ]
            }
        },
        "aggs": {"unique_ports": {"cardinality": {"field": "destination.port"}}},
        "size": 0
    }
    try:
        resp = es.search(index=f"{ES_INDEX_PREFIX}-*", body=port_query)
        unique_ports = resp["aggregations"]["unique_ports"]["value"]
        return unique_ports >= PORT_SCAN_THRESHOLD
    except Exception:
        return False
    
#b2: kiem tra brute force
def check_step_brute_force(es: Elasticsearch,
                            src_ip: str,
                            minutes: int) -> bool:
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term":  {"source.ip":     src_ip}},
                    {"term":  {"event.outcome": "failure"}},
                    {"range": {"@timestamp": {
                        "gte": f"now-{minutes}m"
                    }}},
                ]
            }
        }
    }

    try:
        count = es.count(
            index=f"{ES_INDEX_PREFIX}-*",
            body=query
        )["count"]
        # FIX: dùng BRUTE_FORCE_THRESHOLD thay vì hardcode 3
        return count >= BRUTE_FORCE_THRESHOLD
    except Exception:
        return False

#b3: kiem tra login Seccess
def check_step_login_success(es: Elasticsearch,
                              src_ip: str,
                              minutes: int) -> bool:
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term":  {"source.ip":     src_ip}},
                    {"term":  {"event.outcome": "success"}},
                    {"term":  {"event.type":    "accepted_password"}},
                    {"range": {"@timestamp": {
                        "gte": f"now-{minutes}m"
                    }}},
                ]
            }
        }
    }

    try:
        count = es.count(
            index=f"{ES_INDEX_PREFIX}-*",
            body=query
        )["count"]
        return count > 0
    except Exception:
        return False

#Ham chinh - run correlation engine
def run_correlation(es: Elasticsearch,
                    active_ips: list[str]) -> list[dict]:
    cleanup_expired_states()
    alerts  = []
    minutes = CORRELATION_WINDOW // 60   

    for ip in active_ips:

        #  SHORT-CIRCUIT: check tuần tự, dừng ngay khi False

        # Bước 1: Port scan (cheapest check first)
        has_scan = check_step_port_scan(es, ip, minutes)
        if not has_scan:
            continue   

        # Bước 2: Brute force (chỉ check khi đã có scan)
        has_brute = check_step_brute_force(es, ip, minutes)
        if not has_brute:
            continue   

        # Bước 3: Login success (chỉ check khi có cả scan + brute)
        has_success = check_step_login_success(es, ip, minutes)

        # ALERT LOGIC 

        now             = datetime.now()
        current_alerted = correlation_state.get(ip, {}).get("alerted")
        first_seen      = correlation_state.get(ip, {}).get("first_seen", now)

        # Bước 1 + 2 + 3 → CRITICAL (đã xâm nhập)
        if has_scan and has_brute and has_success:
            if current_alerted != "CRITICAL":
                alert = create_alert(
                    alert_type  = "Targeted Attack",
                    src_ip      = ip,
                    severity    = "CRITICAL",
                    description = (
                        f"Tấn công có chủ đích đa bước từ {ip}: "
                        f"port scan → brute force → đăng nhập thành công"
                    ),
                    extra = {
                        "alert.steps":                ["port_scan",
                                                       "brute_force",
                                                       "login_success"],
                        "alert.chain":                "scan→brute→login",
                        "correlation.window_minutes": minutes,
                        "correlation.first_seen":     first_seen.strftime(
                                                        "%Y-%m-%dT%H:%M:%S"),
                    }
                )
                alerts.append(alert)
                # FIX: lưu cả updated_at và first_seen vào state
                correlation_state[ip] = {
                    "alerted":    "CRITICAL",
                    "steps":      ["port_scan", "brute_force", "login_success"],
                    "first_seen": first_seen,
                    "updated_at": now,
                }
                print(f"  [CRITICAL] Targeted Attack từ {ip}")

        # Bước 1 + 2 → HIGH (đang tấn công, chưa vào được)
        elif has_scan and has_brute:
            if current_alerted not in ("HIGH", "CRITICAL"):
                alert = create_alert(
                    alert_type  = "Targeted Attack In Progress",
                    src_ip      = ip,
                    severity    = "HIGH",
                    description = (
                        f"Tấn công đang tiến hành từ {ip}: "
                        f"port scan → brute force"
                    ),
                    extra = {
                        "alert.steps":                ["port_scan",
                                                       "brute_force"],
                        "alert.chain":                "scan→brute",
                        "correlation.window_minutes": minutes,
                        "correlation.first_seen":     first_seen.strftime(
                                                        "%Y-%m-%dT%H:%M:%S"),
                    }
                )
                alerts.append(alert)
                correlation_state[ip] = {
                    "alerted":    "HIGH",
                    "steps":      ["port_scan", "brute_force"],
                    "first_seen": first_seen,
                    "updated_at": now,
                }
                print(f"  [HIGH] Targeted Attack In Progress từ {ip}")

            elif current_alerted == "HIGH":
                correlation_state[ip]["updated_at"] = now

    return alerts

if __name__ == "__main__":
    import json
    from config.settings import ES_HOST

    es = Elasticsearch(ES_HOST)
    if not es.ping():
        print("[ERROR] Không kết nối được ES")
        sys.exit(1)

    print("[*] Chạy Correlation Engine...\n")
    active = get_active_ips(es, minutes=CORRELATION_WINDOW // 60)
    print(f"[*] Active IPs: {active}\n")

    alerts = run_correlation(es, active)
    print(f"\n[+] Tổng correlation alert: {len(alerts)}")
    for a in alerts:
        print(json.dumps(a, indent=2, ensure_ascii=False))

