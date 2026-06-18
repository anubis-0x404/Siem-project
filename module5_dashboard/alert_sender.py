import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import smtplib
import requests
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from config.settings import ES_INDEX_PREFIX

load_dotenv()

TELEGRAM_TOKEN   = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
EMAIL_SENDER     = os.getenv("EMAIL_SENDER", "")
EMAIL_PASSWORD   = os.getenv("EMAIL_PASSWORD", "")
EMAIL_RECEIVER   = os.getenv("EMAIL_RECEIVER", "")

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
}

def format_telegram_message(alert: dict) -> str:
    severity = alert.get("alert.severity", "UNKNOWN")
    emoji    = SEVERITY_EMOJI.get(severity, "⚪")

    message = (
        f"{emoji} <b>SIEM ALERT — {severity}</b>\n\n"
        f"🔍 <b>Loai:</b> {alert.get('alert.type', 'N/A')}\n"
        f"🌐 <b>IP nguon:</b> <code>{alert.get('source.ip', 'N/A')}</code>\n"
        f"📝 <b>Mo ta:</b> {alert.get('alert.description', 'N/A')}\n"
        f"🕐 <b>Thoi gian:</b> {alert.get('@timestamp', 'N/A')}\n"
    )

    if alert.get("alert.fail_count"):
        message += f"⚡ <b>So lan that bai:</b> {alert['alert.fail_count']}\n"
    if alert.get("alert.chain"):
        message += f"🔗 <b>Chuoi tan cong:</b> {alert['alert.chain']}\n"

    return message

def send_telegram(alert: dict) -> bool:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[WARN] Telegram chua cau hinh trong .env")
        return False

    severity = alert.get("alert.severity", "")
    if severity not in ("HIGH", "CRITICAL"):
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
            print(f"[+] Telegram: Da gui alert {severity} den {TELEGRAM_CHAT_ID}")
            return True
        else:
            print(f"[ERROR] Telegram: {response.status_code} — {response.text}")
            return False

    except requests.Timeout:
        print("[ERROR] Telegram: Timeout sau 10 giay")
        return False
    except Exception as e:
        print(f"[ERROR] Telegram: {e}")
        return False

def send_email(alert: dict) -> bool:
    if not EMAIL_SENDER or not EMAIL_PASSWORD:
        print("[WARN] Email chua cau hinh trong .env")
        return False

    severity = alert.get("alert.severity", "")
    if severity != "CRITICAL":
        return False

    try:
        subject = (f"[SIEM CRITICAL] {alert.get('alert.type', 'Alert')} "
                   f"tu {alert.get('source.ip', 'Unknown')}")

        body = (
            f"SIEM MINI — CANH BAO NGHIEM TRONG\n"
            f"{'='*50}\n\n"
            f"Loai tan cong : {alert.get('alert.type')}\n"
            f"IP nguon      : {alert.get('source.ip')}\n"
            f"Muc do        : {severity}\n"
            f"Thoi gian     : {alert.get('@timestamp')}\n"
            f"Mo ta         : {alert.get('alert.description')}\n\n"
            f"Chi tiet      :\n{json.dumps(alert, indent=2, ensure_ascii=False)}"
        )

        msg = MIMEMultipart()
        msg["From"]    = EMAIL_SENDER
        msg["To"]      = EMAIL_RECEIVER
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)

        print(f"[+] Email: Da gui CRITICAL alert den {EMAIL_RECEIVER}")
        return True

    except smtplib.SMTPAuthenticationError:
        print("[ERROR] Email: Sai tai khoan hoac App Password")
        return False
    except Exception as e:
        print(f"[ERROR] Email: {e}")
        return False

def send_alert(alert: dict) -> None:
    severity = alert.get("alert.severity", "")

    print(f"[*] Xu ly alert: {alert.get('alert.type')} — {severity}")

    if severity == "CRITICAL":
        send_telegram(alert)
        send_email(alert)

    elif severity == "HIGH":
        send_telegram(alert)

    elif severity == "MEDIUM":
        print(f"[INFO] MEDIUM alert logged: {alert.get('alert.description')}")

    else:
        pass

def watch_new_alerts(es: Elasticsearch,
                     check_interval: int = 30) -> None:
    import time
    last_check = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    print(f"[*] Bat dau theo doi alert tu {last_check}")
    print(f"[*] Kiem tra moi {check_interval} giay\n")

    while True:
        try:
            query = {
                "query": {
                    "range": {
                        "@timestamp": { "gt": last_check }
                    }
                },
                "sort": [{ "@timestamp": "asc" }],
                "size": 50
            }

            response = es.search(
                index=f"siem-alerts-*",
                body=query
            )

            hits = response["hits"]["hits"]
            if hits:
                print(f"[+] Phat hien {len(hits)} alert moi")
                for hit in hits:
                    alert = hit["_source"]
                    send_alert(alert)

                last_check = hits[-1]["_source"]["@timestamp"]

        except Exception as e:
            print(f"[ERROR] watch_new_alerts: {e}")

        time.sleep(check_interval)

if __name__ == "__main__":
    from config.settings import ES_HOST

    print("[*] Test gui Telegram...")
    test_alert = {
        "@timestamp":        datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "alert.type":        "SSH Brute Force",
        "alert.severity":    "HIGH",
        "alert.description": "Test alert tu SIEM mini",
        "alert.fail_count":  10,
        "source.ip":         "192.168.1.10",
    }

    result = send_telegram(test_alert)
    print(f"[+] Ket qua gui Telegram: {'Thanh cong' if result else 'That bai'}")

    print("\n[*] Test watch_new_alerts...")
    es = Elasticsearch(ES_HOST)
    if es.ping():
        watch_new_alerts(es, check_interval=10)