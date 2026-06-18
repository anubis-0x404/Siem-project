import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import schedule
from datetime import datetime
from elasticsearch import Elasticsearch
from config.settings import ES_HOST, ES_INDEX_PREFIX, CORRELATION_WINDOW
from module4_detection.rule_based  import run_all_rules
from module4_detection.correlation import run_correlation, get_active_ips
from module5_dashboard.alert_sender import send_alert

#Luu alert vao Elasticsearch
def save_alert(es: Elasticsearch, alert: dict) -> bool:
    try:
        date  = datetime.now().strftime("%Y.%m.%d")
        index = f"siem-alerts-{date}"
        es.index(index=index, document=alert)
        send_alert(alert)
        return True
    except Exception as e:
        print(f"  [ERROR] Luu alert that bai: {e}")
        return False

#1 chu ky hoan chinh
def run_detection_cycle(es: Elasticsearch) -> None:
    now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    print(f"\n{'='*55}")
    print(f"[{now}] Bat dau chu ky detection")
    print(f"{'='*55}")
    minutes     = CORRELATION_WINDOW // 60
    active_ips  = get_active_ips(es, minutes=minutes)

    if not active_ips:
        print("[*] Khong co IP nao dang hoat dong")
        return

    print(f"[*] Phat hien {len(active_ips)} IP dang hoat dong:")
    for ip in active_ips:
        print(f"    • {ip}")

    #Lop 1: Rule-based (single event detection)
    print(f"\n[→] Chay Rule-based engine...")
    rule_alerts = run_all_rules(es, active_ips)

    saved_rule = 0
    for alert in rule_alerts:
        if save_alert(es, alert):
            saved_rule += 1

    print(f"[✓] Rule-based: {len(rule_alerts)} alert, "
          f"{saved_rule} luu thanh cong")
    
    #Lop 2: Correlation (multi-event chain detection)
    print(f"\n[→] Chay Correlation engine...")
    corr_alerts = run_correlation(es, active_ips)

    saved_corr = 0
    for alert in corr_alerts:
        if save_alert(es, alert):
            saved_corr += 1

    print(f"[✓] Correlation: {len(corr_alerts)} alert, "
          f"{saved_corr} luu thanh cong")

    # ④ Tong ket chu ky
    total_saved = saved_rule + saved_corr
    print(f"\n[+] Chu ky hoan thanh: "
          f"{saved_rule} rule + {saved_corr} correlation = "
          f"{total_saved} alert da luu vao siem-alerts-*")
#chay 1 lan
def run_once(es: Elasticsearch) -> None:
    run_detection_cycle(es)

#Chay
def run_scheduled(es: Elasticsearch, interval_seconds: int = 30) -> None:
    print(f"[*] Detection Engine khoi dong")
    print(f"[*] Chu ky kiem tra: {interval_seconds} giay")
    print(f"[*] Correlation window: {CORRELATION_WINDOW // 60} phut")
    print(f"[*] Nhan Ctrl+C de dung\n")

    def safe_detection_cycle():
        try:
            run_detection_cycle(es)
        except Exception as e:
            print(f"\n[ERROR] Detection cycle gap loi, "
                  f"engine tiep tuc o chu ky sau: {e}")
    
    schedule.every(interval_seconds).seconds.do(safe_detection_cycle)
    safe_detection_cycle()
    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Detection Engine da dung sach")

if __name__ == "__main__":
    es = Elasticsearch(ES_HOST)

    if not es.ping():
        print("[ERROR] Khong ket noi duoc Elasticsearch")
        print(f"[INFO] Kiem tra ES dang chay tai: {ES_HOST}")
        sys.exit(1)

    print("[*] Ket noi Elasticsearch thanh cong\n")

    # --schedule → chay lien tuc; khong co flag → chay 1 lan
    if "--schedule" in sys.argv:
        run_scheduled(es, interval_seconds=30)
    else:
        run_once(es) # type: ignore