import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from elasticsearch import Elasticsearch
from config.settings import ES_HOST
from module3_storage.index_template import create_index_template
from module4_detection.engine import run_scheduled

def print_banner() -> None:
    print("=" * 60)
    print("   MINI SIEM — Hệ thống giám sát và phát hiện tấn công")
    print("   Rule-based Detection & Event Correlation")
    print("=" * 60)
    print(f"   Elasticsearch : {ES_HOST}")
    print(f"   Detection     : Rule-based + Correlation")
    print(f"   Alert channel : Telegram")
    print("=" * 60)
    print()

# ── Kiểm tra môi trường trước khi chạy ───────────────────────
def check_prerequisites(es: Elasticsearch) -> bool:
    print("[*] Kiểm tra điều kiện khởi động...")

    # Kiểm tra kết nối ES
    if not es.ping():
        print(f"[ERROR] Không kết nối được Elasticsearch tại {ES_HOST}")
        print("[INFO] Kiểm tra: sudo systemctl status elasticsearch")
        return False
    print("[+] Elasticsearch: kết nối OK")

    # Đảm bảo index template tồn tại
    try:
        if not es.indices.exists_index_template(name="siem-logs-template"):
            print("[*] Index template chưa có, đang tạo...")
            create_index_template(es)
        else:
            print("[+] Index template: đã tồn tại")
    except Exception as e:
        print(f"[ERROR] Lỗi kiểm tra index template: {e}")
        return False

    print("[+] Tất cả điều kiện đã sẵn sàng\n")
    return True

def main() -> None:
    print_banner()
    es = Elasticsearch(ES_HOST)

    if not check_prerequisites(es):
        print("[FATAL] Hệ thống không thể khởi động. Dừng lại.")
        sys.exit(1)

    print("[*] Đang khởi động Detection Engine...")
    try:
        # Khởi động Detection Engine — chạy liên tục mỗi 30 giây
        run_scheduled(es, interval_seconds=30)
    except KeyboardInterrupt:
        print("\n[*] Đã nhận lệnh dừng (Ctrl+C). Hệ thống Mini SIEM đang tắt an toàn...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[FATAL] Engine gặp lỗi không xác định và phải dừng lại: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()