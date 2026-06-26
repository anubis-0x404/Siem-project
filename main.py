import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import time
from datetime import datetime
from elasticsearch import Elasticsearch

from config.settings import ES_HOST, ES_INDEX_PREFIX
from module3_storage.index_template import create_index_template, check_legacy_indices
from module3_storage.es_client      import ensure_template_exists, ingest_new_logs, query_recent_events
from module4_detection.rule_based   import run_all_rules
from module4_detection.correlation  import run_correlation, get_active_ips
from module4_detection.engine       import run_detection_cycle, run_scheduled, save_alert
from module5_dashboard.alert_sender import send_telegram

KIBANA_URL = "http://192.168.220.10:5601"

# ── Banner ────────────────────────────────────────────────────
def print_banner() -> None:
    banner = r"""
   _____ _____ _____ __  __        _      _
  / ____|_   _|  ___|  \/  |      (_)    (_)
 | (___   | | | |__ | \  / |      _ _ __  _
  \___ \  | | |  __|| |\/| |     | | '_ \| |
  ____) |_| |_| |___| |  | |     | | | | | |
 |_____/|_____|_____|_|  |_|     |_|_| |_|_|

  Mini SIEM — Rule-based Detection & Event Correlation
  Version: 1.0
"""
    print(banner)

# ── Hiển thị trạng thái hệ thống ─────────────────────────────
def print_status(es: Elasticsearch) -> None:
    print("=" * 56)
    print(f"[*] Elasticsearch : {ES_HOST}")
    print(f"[*] Index prefix  : {ES_INDEX_PREFIX}-*")
    print(f"[*] Kibana        : {KIBANA_URL}")
    try:
        log_count   = es.count(index=f"{ES_INDEX_PREFIX}-*")["count"]
        alert_count = es.count(index="siem-alerts-*")["count"]
        print(f"[*] Tong log      : {log_count}")
        print(f"[*] Tong alert    : {alert_count}")
    except Exception:
        print("[*] Tong log/alert: chua co index")
    print("=" * 56)

# ── Menu ───────────────────────────────────────────────────────
def print_menu(es: Elasticsearch) -> None:
    print_status(es)
    print()
    print("    [1] Kiem tra ket noi Elasticsearch")
    print("    [2] Tao/cap nhat Index Template")
    print("    [3] Nap log moi vao Elasticsearch (ingest)")
    print("    [4] Chay Rule-based Detection (1 lan)")
    print("    [5] Chay Correlation Detection (1 lan)")
    print("    [6] Chay 1 chu ky Detection day du (ingest + rule + correlation)")
    print("    [7] Chay giam sat lien tuc (Detection Engine --schedule)")
    print("    [8] Gui canh bao Telegram")
    print("    [9] Mo Kibana Dashboard")
    print("    [0] Thoat")
    print()

# ── Từng chức năng menu ──────────────────────────────────────

def action_check_connection(es: Elasticsearch) -> None:
    print("\n[*] Dang kiem tra ket noi Elasticsearch...")
    if es.ping():
        info = es.info()
        print(f"[+] Ket noi thanh cong — version {info['version']['number']}")
    else:
        print("[ERROR] Khong ket noi duoc Elasticsearch")
        print(f"[INFO] Kiem tra: sudo systemctl status elasticsearch")

def action_create_template(es: Elasticsearch) -> None:
    print("\n[*] Dang tao/cap nhat index template...")
    create_index_template(es)
    check_legacy_indices(es)

def action_ingest(es: Elasticsearch) -> None:
    print("\n[*] Dang nap log moi vao Elasticsearch...")
    count = ingest_new_logs(es)
    if count:
        print(f"[+] Da nap {count} document moi")
    else:
        print("[*] Khong co log moi nao de nap")

def action_rule_based(es: Elasticsearch) -> None:
    print("\n[*] Dang chay Rule-based Detection...")
    active_ips = get_active_ips(es, minutes=15)
    if not active_ips:
        print("[*] Khong co IP nao dang hoat dong")
        return
    print(f"[*] Kiem tra {len(active_ips)} IP: {active_ips}")
    alerts = run_all_rules(es, active_ips)
    for alert in alerts:
        save_alert(es, alert)
    print(f"[+] Hoan thanh: {len(alerts)} alert duoc tao")
    if alerts:
        print(f"[i] Canh bao HIGH/CRITICAL da duoc gui ve Telegram")
        print(f"[i] Xem chi tiet tren Kibana: {KIBANA_URL}")

def action_correlation(es: Elasticsearch) -> None:
    print("\n[*] Dang chay Correlation Detection...")
    active_ips = get_active_ips(es, minutes=15)
    if not active_ips:
        print("[*] Khong co IP nao dang hoat dong")
        return
    alerts = run_correlation(es, active_ips)
    for alert in alerts:
        save_alert(es, alert)
    print(f"[+] Hoan thanh: {len(alerts)} correlation alert duoc tao")
    if alerts:
        print(f"[i] Canh bao CRITICAL da duoc gui ve Telegram")
        print(f"[i] Xem chi tiet tren Kibana: {KIBANA_URL}")

def action_full_cycle(es: Elasticsearch) -> None:
    print("\n[*] Dang chay 1 chu ky Detection day du...")
    run_detection_cycle(es)
    print(f"\n[i] Mo Kibana de xem dashboard truc quan: {KIBANA_URL}")

def action_run_scheduled(es: Elasticsearch) -> None:
    print("\n[*] Khoi dong giam sat lien tuc...")
    print(f"[i] Theo doi qua Kibana: {KIBANA_URL}")
    print(f"[i] Canh bao HIGH/CRITICAL se duoc gui ve Telegram tu dong")
    print("[i] Nhan Ctrl+C de dung va quay lai menu\n")
    try:
        run_scheduled(es, interval_seconds=30)
    except KeyboardInterrupt:
        print("\n[*] Da dung giam sat, quay lai menu chinh")

def action_send_alert(es: Elasticsearch) -> None:
    print("\n[*] Tim alert moi nhat trong Elasticsearch...")
 
    try:
        # Query alert mới nhất từ siem-alerts-*
        response = es.search(
            index="siem-alerts-*",
            body={
                "query": {"match_all": {}},
                "sort":  [{"@timestamp": {"order": "desc"}}],
                "size":  1
            }
        )
        hits = response["hits"]["hits"]
 
        # Trường hợp chưa có alert nào
        if not hits:
            print("[!] Chua co alert nao trong siem-alerts-*")
            print("[i] Hay chay option [6] truoc de tao alert tu log thuc te")
            print(f"[i] Hoac thuc hien tan cong tu Kali roi chay lai")
            return 
 
        # Lấy alert mới nhất
        alert = hits[0]["_source"]
 
        # Hiển thị thông tin alert trước khi gửi
        print("\n" + "-" * 50)
        print("[+] Tim thay alert — thong tin chi tiet:")
        print(f"    Loai       : {alert.get('alert.type',        'N/A')}")
        print(f"    Severity   : {alert.get('alert.severity',    'N/A')}")
        print(f"    IP tan cong: {alert.get('source.ip',         'N/A')}")
        print(f"    Mo ta      : {alert.get('alert.description', 'N/A')}")
        print(f"    Thoi gian  : {alert.get('@timestamp',        'N/A')}")
        if alert.get("alert.fail_count"):
            print(f"    So lan fail: {alert['alert.fail_count']}")
        if alert.get("alert.chain"):
            print(f"    Chuoi tan cong: {alert['alert.chain']}")
        print("-" * 50)
 
        # Gửi Telegram
        print("\n[*] Dang gui len Telegram...")
        result = send_telegram(alert)
 
        if result:
            print("[+] Gui thanh cong — kiem tra Telegram cua ban")
        else:
            print("[ERROR] Gui that bai")
            print("[i] Kiem tra TELEGRAM_BOT_TOKEN va TELEGRAM_CHAT_ID trong .env")
            print("[i] Chay: cat ~/siem_project/.env | grep TELEGRAM")
 
    except Exception as e:
        print(f"[ERROR] Loi khi truy van Elasticsearch: {e}")
        print("[i] Kiem tra Elasticsearch dang chay: sudo systemctl status elasticsearch")

def action_open_kibana() -> None:
    print(f"\n[i] Mo trinh duyet va truy cap:")
    print(f"    {KIBANA_URL}")
    print(f"    → Dashboard: SIEM — Security Overview")

def check_prerequisites(es: Elasticsearch) -> bool:
    print("[*] Kiem tra dieu kien khoi dong he thong...")

    if not es.ping():
        print(f"[ERROR] Khong ket noi duoc Elasticsearch tai {ES_HOST}")
        print("[INFO] Kiem tra: sudo systemctl status elasticsearch")
        return False
    print("[+] Elasticsearch: OK")

    if not ensure_template_exists(es):
        print("[ERROR] Khong dam bao duoc index template")
        return False
    print("[+] Index template: OK")

    print("[+] He thong san sang\n")
    return True


def main() -> None:
    print_banner()

    es = Elasticsearch(ES_HOST)

    if not check_prerequisites(es):
        print("[FATAL] He thong khong the khoi dong. Dung lai.")
        sys.exit(1)

    actions = {
        "1": lambda: action_check_connection(es),
        "2": lambda: action_create_template(es),
        "3": lambda: action_ingest(es),
        "4": lambda: action_rule_based(es),
        "5": lambda: action_correlation(es),
        "6": lambda: action_full_cycle(es),
        "7": lambda: action_run_scheduled(es),
        "8": lambda: action_send_alert(es),
        "9": lambda: action_open_kibana(),
    }

    while True:
        print_menu(es)
        choice = input("[?] Chon mot tuy chon > ").strip()

        if choice == "0":
            print("\n[*] Tam biet!")
            break
        elif choice in actions:
            actions[choice]()
            input("\n[Enter] de quay lai menu...")
        else:
            print("\n[!] Lua chon khong hop le, thu lai")

        print()

if __name__ == "__main__":
    main()