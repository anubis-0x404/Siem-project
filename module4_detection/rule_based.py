import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime
from elasticsearch import Elasticsearch
from config.settings import (
    ES_INDEX_PREFIX,
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW,
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_WINDOW,
)
_rule_cooldown: dict = {}
COOLDOWN_SECONDS = 300

def _is_in_cooldown(alert_type: str, src_ip: str) -> bool:
    key = f"{alert_type}:{src_ip}"
    last_alerted = _rule_cooldown.get(key)
    if last_alerted is None:
        return False
    elapsed = (datetime.now() - last_alerted).total_seconds()
    return elapsed < COOLDOWN_SECONDS

def _set_cooldown(alert_type: str, src_ip: str) -> None:
    """Ghi nhận thời điểm vừa alert để tính cooldown."""
    key = f"{alert_type}:{src_ip}"
    _rule_cooldown[key] = datetime.now()

# Ham tao alert document
def create_alert(alert_type: str, src_ip: str,
                 severity: str, description: str,
                 extra: dict = None) -> dict:
    ts = datetime.now()
    alert = {
        "alert.id": (
            f"{alert_type.lower().replace(' ', '_')}"
            f"-{src_ip}"
            f"-{ts.strftime('%Y%m%d%H%M%S%f')}"
        ),
        "@timestamp":    ts.strftime("%Y-%m-%dT%H:%M:%S"),
        "event.kind":    "alert",
        "alert.type":    alert_type,
        "alert.severity": severity,
        "alert.description": description,
        "source.ip":     src_ip,
        "tags": ["siem-alert", alert_type.lower().replace(" ", "-")],
    }
    if extra:
        alert.update(extra)
    return alert

# Rule 1: SSH brute force
def check_brute_force(es: Elasticsearch, src_ip: str) -> dict | None:
     # Cooldown — không query ES nếu đã alert gần đây
    if _is_in_cooldown("SSH Brute Force", src_ip):
        return None
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term":  {"source.ip":     src_ip}},
                    {"term":  {"event.outcome": "failure"}},
                    {"terms": {"event.type": [
                        "failed_password",
                        "invalid_user"
                    ]}},
                    {"range": {"@timestamp": {
                        "gte": f"now-{BRUTE_FORCE_WINDOW}s"
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
        if count >= BRUTE_FORCE_THRESHOLD:
            _set_cooldown("SSH Brute Force", src_ip)   # Đánh dấu cooldown
            return create_alert(
                alert_type  = "SSH Brute Force",
                src_ip      = src_ip,
                severity    = "HIGH",
                description = (
                    f"Phát hiện {count} lần đăng nhập thất bại "
                    f"từ {src_ip} trong {BRUTE_FORCE_WINDOW} giây"
                ),
                extra = {
                    "alert.fail_count":   count,
                    "alert.threshold":    BRUTE_FORCE_THRESHOLD,
                    "alert.time_window":  BRUTE_FORCE_WINDOW,
                    "destination.port":   22,
                    "network.protocol":   "ssh",
                }
            )
    except Exception as e:
        print(f"[ERROR] check_brute_force({src_ip}): {e}")

    return None  

# Rule 2: Port Scan
def check_port_scan(es: Elasticsearch, src_ip: str) -> dict | None:
     # ① Cooldown check
    if _is_in_cooldown("Port Scan", src_ip):
        return None

    query = {
        "query": {
            "bool": {
                "must": [
                    {"term":  {"source.ip": src_ip}},
                    {"range": {"@timestamp": {
                        "gte": f"now-{PORT_SCAN_WINDOW}s"
                    }}},
                ]
            }
        },
        "aggs": {
            "unique_ports": {
                "cardinality": {        # ② Đếm unique destination.port
                    "field": "destination.port"
                }
            }
        },
        "size": 0   # ③ Không cần document, chỉ cần aggregation
    }

    try:
        response = es.search(
            index=f"{ES_INDEX_PREFIX}-*",
            body=query
        )
        unique_port_count = (
            response["aggregations"]["unique_ports"]["value"]
        )

        if unique_port_count >= PORT_SCAN_THRESHOLD:
            _set_cooldown("Port Scan", src_ip)   # ④ Đánh dấu cooldown
            return create_alert(
                alert_type  = "Port Scan",
                src_ip      = src_ip,
                severity    = "MEDIUM",
                description = (
                    f"Phát hiện quét {unique_port_count} cổng khác nhau "
                    f"từ {src_ip} trong {PORT_SCAN_WINDOW} giây"
                ),
                extra = {
                    "alert.unique_ports":  unique_port_count,
                    "alert.threshold":     PORT_SCAN_THRESHOLD,
                    "alert.time_window":   PORT_SCAN_WINDOW,
                }
            )

    except Exception as e:
        print(f"[ERROR] check_port_scan({src_ip}): {e}")

    return None   # Explicit return

# Ham kiem tra tat ca rules
def run_all_rules(es: Elasticsearch, active_ips: list[str]) -> list[dict]:
    alerts = []
    for ip in active_ips:
        alert = check_brute_force(es, ip)
        if alert:
            print(f"  [ALERT] SSH Brute Force từ {ip}")
            alerts.append(alert)

        alert = check_port_scan(es, ip)
        if alert:
            print(f"  [ALERT] Port Scan từ {ip}")
            alerts.append(alert)

    return alerts

if __name__ == "__main__":
    from config.settings import ES_HOST
    import json
    from config.settings import ES_HOST
    es = Elasticsearch(ES_HOST)
    if not es.ping():
        print("[ERROR] Không kết nối được ES")
        sys.exit(1)
    test_ips = ["192.168.1.10", "192.168.1.5"]
    print(f"[*] Kiem tra {len(test_ips)} IP...\n")
    alerts = run_all_rules(es, test_ips)
    print(f"\n[+] Tong alert: {len(alerts)}")
    for a in alerts:
        print(json.dumps(a, indent=2, ensure_ascii=False))