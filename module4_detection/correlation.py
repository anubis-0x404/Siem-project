import sys
import os
import logging
from datetime import datetime, timezone
from elasticsearch import Elasticsearch

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import (
    ES_INDEX_PREFIX,
    CORRELATION_WINDOW,
    BRUTE_FORCE_THRESHOLD,
    PORT_SCAN_THRESHOLD,
)
from module4_detection.rule_based import create_alert

logger = logging.getLogger("SIEM-Correlation")

correlation_state: dict = {}
STATE_TTL_MINUTES = 20

def cleanup_expired_states(ttl_minutes: int = STATE_TTL_MINUTES) -> None:
    now = datetime.now(timezone.utc)
    expired_ips = [
        ip for ip, data in correlation_state.items()
        if (now - data.get("updated_at", now)).total_seconds() > ttl_minutes * 60
    ]
    for ip in expired_ips:
        del correlation_state[ip]
        logger.info(f"Giải phóng state hết hạn cho IP: {ip}")

def get_active_ips(es: Elasticsearch, minutes: int = 15) -> list[str]:
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
                    "size": 500
                }
            }
        },
        "size": 0
    }

    try:
        response = es.search(index=f"{ES_INDEX_PREFIX}-*", body=query)
        buckets = response["aggregations"]["active_ips"]["buckets"]
        return [b["key"] for b in buckets]
    except Exception as e:
        logger.error(f"Lỗi khi lấy danh sách IP hoạt động (get_active_ips): {e}")
        return []

def check_step_port_scan(es: Elasticsearch, src_ip: str, minutes: int) -> bool:
    signature_query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"source.ip": src_ip}},
                    {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}},
                    {"wildcard": {"rule.name": {"value": "*scan*", "case_insensitive": True}}}
                ]
            }
        }
    }

    try:
        count = es.count(index=f"{ES_INDEX_PREFIX}-*", body=signature_query)["count"]
        if count > 0:
            return True
    except Exception as e:
        logger.debug(f"Truy vấn signature scan cho {src_ip} gặp lỗi nhẹ (có thể do thiếu field rule.name): {e}")

    port_query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"source.ip": src_ip}},
                    {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}},
                ]
            }
        },
        "aggs": {
            "unique_ports": {
                "cardinality": {
                    "field": "destination.port"
                }
            }
        },
        "size": 0
    }

    try:
        resp = es.search(index=f"{ES_INDEX_PREFIX}-*", body=port_query)
        unique_ports = resp["aggregations"]["unique_ports"]["value"]
        return unique_ports >= PORT_SCAN_THRESHOLD
    except Exception as e:
        logger.error(f"Lỗi truy vấn đếm port (cardinality) cho {src_ip}: {e}")
        return False

def check_step_brute_force(es: Elasticsearch, src_ip: str, minutes: int) -> bool:
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"source.ip": src_ip}},
                    {"term": {"event.outcome": "failure"}},
                    {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}},
                ]
            }
        }
    }

    try:
        count = es.count(index=f"{ES_INDEX_PREFIX}-*", body=query)["count"]
        return count >= BRUTE_FORCE_THRESHOLD
    except Exception as e:
        logger.error(f"Lỗi kiểm tra brute force step cho {src_ip}: {e}")
        return False

def check_step_login_success(es: Elasticsearch, src_ip: str, minutes: int) -> bool:
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"source.ip": src_ip}},
                    {"term": {"event.outcome": "success"}},
                    {"term": {"event.type": "accepted_password"}},
                    {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}},
                ]
            }
        }
    }

    try:
        count = es.count(index=f"{ES_INDEX_PREFIX}-*", body=query)["count"]
        return count > 0
    except Exception as e:
        logger.error(f"Lỗi kiểm tra thành công đăng nhập cho {src_ip}: {e}")
        return False

def run_correlation(es: Elasticsearch, active_ips: list[str]) -> list[dict]:
    cleanup_expired_states()
    alerts = []
    minutes = CORRELATION_WINDOW // 60

    for ip in active_ips:
        has_scan = check_step_port_scan(es, ip, minutes)
        if not has_scan:
            continue

        has_brute = check_step_brute_force(es, ip, minutes)
        if not has_brute:
            continue

        has_success = check_step_login_success(es, ip, minutes)

        now = datetime.now(timezone.utc)
        state_data = correlation_state.get(ip, {})
        current_alerted = state_data.get("alerted")
        first_seen = state_data.get("first_seen", now)

        if has_success:
            if current_alerted != "CRITICAL":
                alert = create_alert(
                    alert_type="Targeted Attack",
                    src_ip=ip,
                    severity="CRITICAL",
                    description=(
                        f"Phát hiện chuỗi tấn công có chủ đích nguy hiểm từ {ip}: "
                        f"Port Scan → Brute Force → Chiếm quyền điều khiển thành công."
                    ),
                    extra={
                        "alert.steps": ["port_scan", "brute_force", "login_success"],
                        "alert.chain": "scan→brute→login",
                        "correlation.window_minutes": minutes,
                        "correlation.first_seen": first_seen.strftime("%Y-%m-%dT%H:%M:%S"),
                    }
                )

                alerts.append(alert)

                correlation_state[ip] = {
                    "alerted": "CRITICAL",
                    "steps": ["port_scan", "brute_force", "login_success"],
                    "first_seen": first_seen,
                    "updated_at": now,
                }

                logger.critical(
                    f"PHÁT HIỆN XÂM NHẬP THÀNH CÔNG (Targeted Attack) từ IP: {ip}"
                )

        else:
            if current_alerted not in ("HIGH", "CRITICAL"):
                alert = create_alert(
                    alert_type="Targeted Attack In Progress",
                    src_ip=ip,
                    severity="HIGH",
                    description=(
                        f"Phát hiện chuỗi tấn công đang diễn ra từ {ip}: "
                        f"Port Scan → Đang tiến hành Brute Force."
                    ),
                    extra={
                        "alert.steps": ["port_scan", "brute_force"],
                        "alert.chain": "scan→brute",
                        "correlation.window_minutes": minutes,
                        "correlation.first_seen": first_seen.strftime("%Y-%m-%dT%H:%M:%S"),
                    }
                )

                alerts.append(alert)

                correlation_state[ip] = {
                    "alerted": "HIGH",
                    "steps": ["port_scan", "brute_force"],
                    "first_seen": first_seen,
                    "updated_at": now,
                }

                logger.warning(
                    f"Phát hiện chuỗi tấn công diện rộng đang diễn ra (High Severity) từ IP: {ip}"
                )

            elif current_alerted == "HIGH":
                correlation_state[ip]["updated_at"] = now

    return alerts

if __name__ == "__main__":
    import json
    from config.settings import ES_HOST

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s'
    )

    es = Elasticsearch(ES_HOST)

    if not es.ping():
        logger.critical("Không thể kết nối đến Elasticsearch Cluster.")
        sys.exit(1)

    logger.info("Chạy thử nghiệm Correlation Engine độc lập...")

    active = get_active_ips(
        es,
        minutes=CORRELATION_WINDOW // 60
    )

    logger.info(f"Danh sách IP ghi nhận hoạt động: {active}")

    alerts = run_correlation(es, active)

    logger.info(f"Chu kỳ hoàn tất. Tạo ra {len(alerts)} correlation alert mới.")

    for a in alerts:
        print(json.dumps(a, indent=2, ensure_ascii=False))