import sys
import os
import time
import signal
import argparse
import logging
from datetime import datetime, timezone
from elasticsearch import Elasticsearch

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import ES_HOST, ES_INDEX_PREFIX, CORRELATION_WINDOW
from module4_detection.rule_based import run_all_rules
from module4_detection.correlation import run_correlation, get_active_ips
from module5_dashboard.alert_sender import send_alert
from module3_storage.es_client import ingest_new_logs, ensure_template_exists

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("SIEM-Engine")

is_running = True

def handle_shutdown_signal(signum, frame):
    global is_running
    logger.info(f"Nhận tín hiệu dừng hệ thống (Signal: {signum}). Đang dọn dẹp và thoát...")
    is_running = False

signal.signal(signal.SIGINT, handle_shutdown_signal)
signal.signal(signal.SIGTERM, handle_shutdown_signal)

def save_alert(es: Elasticsearch, alert: dict) -> bool:
    try:
        date = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        index = f"siem-alerts-{date}"
        es.index(index=index, document=alert)
        send_alert(alert)
        return True
    except Exception as e:
        logger.error(f"Lưu alert thất bại cho IP {alert.get('source.ip')}: {e}")
        return False

def run_detection_cycle(es: Elasticsearch) -> None:
    logger.info("-" * 50)
    logger.info("BẮT ĐẦU CHU KỲ PHÁT HIỆN")
    logger.info("-" * 50)

    try:
        ingested = ingest_new_logs(es)
        if ingested:
            logger.info(f"Đã nạp {ingested} log mới vào Elasticsearch.")
    except Exception as e:
        logger.error(f"Lỗi khi nạp log mới (ingest_new_logs): {e}")

    minutes = CORRELATION_WINDOW // 60
    try:
        active_ips = get_active_ips(es, minutes=minutes)
    except Exception as e:
        logger.error(f"Không thể lấy danh sách IP hoạt động: {e}")
        return

    if not active_ips:
        logger.info("Không ghi nhận IP nào hoạt động trong Window thời gian.")
        return

    logger.info(f"Phát hiện {len(active_ips)} IP đang tương tác: {', '.join(active_ips)}")

    logger.info("Khởi chạy: Rule-based Engine...")
    try:
        rule_alerts = run_all_rules(es, active_ips)
        saved_rule = 0
        for alert in rule_alerts:
            if save_alert(es, alert):
                saved_rule += 1
        logger.info(f"[Kết quả] Rule-based: Tạo {len(rule_alerts)} alert, lưu thành công {saved_rule}.")
    except Exception as e:
        logger.error(f"Lỗi tại Rule-based: {e}")
        saved_rule = 0
        rule_alerts = []

    logger.info("Khởi chạy: Correlation Engine...")
    try:
        corr_alerts = run_correlation(es, active_ips)
        saved_corr = 0
        for alert in corr_alerts:
            if save_alert(es, alert):
                saved_corr += 1
        logger.info(f"[Kết quả] Correlation: Tạo {len(corr_alerts)} alert, lưu thành công {saved_corr}.")
    except Exception as e:
        logger.error(f"Lỗi tại Correlation: {e}")
        saved_corr = 0
        corr_alerts = []

    total_saved = saved_rule + saved_corr
    logger.info(f"Tổng số alert đã ghi nhận: {total_saved}")

def run_once(es: Elasticsearch) -> None:
    run_detection_cycle(es)

def run_scheduled(es: Elasticsearch, interval_seconds: int = 30) -> None:
    import schedule

    logger.info("Detection Engine đã kích hoạt.")
    logger.info(f"Chu kỳ quét hệ thống: {interval_seconds} giây.")
    logger.info(f"(Correlation window): {CORRELATION_WINDOW // 60} phút.")

    def safe_detection_cycle():
        try:
            run_detection_cycle(es)
        except Exception as e:
            logger.critical(f"Chu kỳ Detection lỗi, tự động khôi phục ở chu kỳ sau: {e}")

    schedule.every(interval_seconds).seconds.do(safe_detection_cycle)

    safe_detection_cycle()

    while is_running:
        schedule.run_pending()
        time.sleep(1)

    logger.info("Hệ thống đã dừng hoàn toàn.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SIEM Detection Engine Core")
    parser.add_argument("--schedule", action="store_true", help="Chạy hệ thống liên tục định kỳ (Production mode)")
    parser.add_argument("--interval", type=int, default=30, help="Thời gian lặp lại chu kỳ quét (giây)")
    args = parser.parse_args()

    es = Elasticsearch(ES_HOST)

    if not es.ping():
        logger.critical(f"Không thể kết nối tới Elasticsearch tại địa chỉ: {ES_HOST}. Hệ thống dừng lại.")
        sys.exit(1)

    logger.info(f"Kết nối thành công tới Elasticsearch: {ES_HOST}")

    if not ensure_template_exists(es):
        logger.critical("Index template lỗi hoặc không tồn tại. Dừng hệ thống")
        sys.exit(1)

    logger.info("Kiểm tra cấu trúc Index Template: ĐẠT YÊU CẦU.\n")

    if args.schedule:
        run_scheduled(es, interval_seconds=args.interval)
    else:
        logger.info("Chạy hệ thống 1 lần duy nhất.")
        run_once(es)