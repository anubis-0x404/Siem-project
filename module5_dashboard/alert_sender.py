import sys
import os
import html
import logging
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from config.settings import ES_INDEX_PREFIX
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

load_dotenv()
logger = logging.getLogger("SIEM-AlertSender")

TELEGRAM_TOKEN   = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
}
SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}
TELEGRAM_MIN_SEVERITY = "MEDIUM"
def format_telegram_message(alert: dict) -> str:
    severity = alert.get("alert.severity", "UNKNOWN")
    emoji    = SEVERITY_EMOJI.get(severity, "⚪")

    alert_type = html.escape(str(alert.get('alert.type', 'N/A')))
    src_ip     = html.escape(str(alert.get('source.ip', 'N/A')))
    desc       = html.escape(str(alert.get('alert.description', 'N/A')))
    timestamp  = html.escape(str(alert.get('@timestamp', 'N/A')))

    message = (
        f"{emoji} <b>SIEM ALERT — {severity}</b>\n\n"
        f"🔍 <b>Loại:</b> {alert_type}\n"
        f"🌐 <b>IP nguồn:</b> <code>{src_ip}</code>\n"
        f"📝 <b>Mô tả:</b> {desc}\n"
        f"🕐 <b>Thời gian:</b> {timestamp}\n"
    )

    if alert.get("alert.fail_count"):
        message += f"⚡ <b>Số lần thất bại:</b> {alert['alert.fail_count']}\n"

    if alert.get("alert.unique_ports"):
        message += f"🔎 <b>Số cổng quét:</b> {alert['alert.unique_ports']}\n"

    if alert.get("alert.chain"):
        chain = html.escape(str(alert["alert.chain"]))
        message += f"🔗 <b>Chuỗi tấn công:</b> {chain}\n"

    return message


def send_telegram(alert: dict) -> bool:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[WARN] Telegram chua cau hinh trong .env (.env path: "
              f"{_env_path}) — KHONG gui duoc canh bao thuc te")
        return False

    severity  = alert.get("alert.severity", "LOW")
    cur_rank = SEVERITY_RANK.get(severity,               0)
    min_rank = SEVERITY_RANK.get(TELEGRAM_MIN_SEVERITY,  2)

    if cur_rank < min_rank:
        print(f"[INFO] Bo qua Telegram cho severity {severity} "
              f"(duoi nguong {TELEGRAM_MIN_SEVERITY})")
        return False

    try:
        url     = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {
            "chat_id":    TELEGRAM_CHAT_ID,
            "text":       format_telegram_message(alert),
            "parse_mode": "HTML",
        }
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            logger.info(
                f"Telegram: Đã gửi alert [{severity}] "
                f"→ {alert.get('alert.type')} từ {alert.get('source.ip')}"
            )
            return True
        else:
            logger.error(
                f"Telegram trả về lỗi {response.status_code}: {response.text}"
            )
            return False

    except requests.Timeout:
        logger.error("Telegram: Timeout sau 10 giây — kiểm tra mạng ra internet")
        return False
    except requests.ConnectionError as e:
        logger.error(f"Telegram: Không kết nối được internet: {e}")
        return False
    except Exception as e:
        logger.error(f"Telegram: Lỗi không xác định: {e}")
        return False

def send_alert(alert: dict) -> None:
    severity = alert.get("alert.severity", "")
    print(f"[*] Xu ly alert: {alert.get('alert.type')} — {severity}")
    sent = send_telegram(alert)

    if not sent and severity in ("MEDIUM", "LOW", "INFO"):
        print(f"[INFO] Alert {severity} duoc ghi log, khong gui Telegram: "
              f"{alert.get('alert.description')}")


def watch_new_alerts(es: Elasticsearch, check_interval: int = 30) -> None:
    last_check = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    logger.info(f"Alert daemon khởi động — theo dõi từ: {last_check}")
    logger.info(f"Chu kỳ kiểm tra: {check_interval} giây")
 
    import time
    while True:
        try:
            query = {
                "query": {
                    "range": {
                        "@timestamp": {"gt": last_check}
                    }
                },
                "sort": [{"@timestamp": "asc"}],
                "size": 200
            }
            response = es.search(index="siem-alerts-*", body=query)
            hits     = response["hits"]["hits"]
 
            if hits:
                logger.info(f"Phát hiện {len(hits)} alert mới")
                for hit in hits:
                    send_alert(hit["_source"])
 
                # Cập nhật mốc thời gian cho lần poll tiếp theo
                last_check = hits[-1]["_source"]["@timestamp"]
 
        except Exception as e:
            logger.error(f"Lỗi trong watch_new_alerts: {e}")
 
        time.sleep(check_interval)


if __name__ == "__main__":
    import argparse
    from config.settings import ES_HOST
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

    parser = argparse.ArgumentParser(description="SIEM Alert Sender Module")
    parser.add_argument("--watch", action="store_true", help="Kích hoạt chế độ standalone daemon chủ động quét tìm alert mới")
    parser.add_argument("--interval", type=int, default=30, help="Chu kỳ quét tìm alert (giây)")
    args = parser.parse_args()

    if args.watch:
        es = Elasticsearch(ES_HOST)
        if not es.ping():
            logger.critical("Không thể thiết lập kết nối đến Elasticsearch để giám sát Alert.")
            sys.exit(1)
        try:
            watch_new_alerts(es, check_interval=args.interval)
        except KeyboardInterrupt:
            logger.info("Đã nhận tín hiệu dừng dịch vụ alert daemon.")
    else:
        logger.info("Module Alert Sender đang ở chế độ thư viện. Nhúng thành công vào SIEM Engine Core.")