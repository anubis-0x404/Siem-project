##AUTH_LOG_PATH = "/var/log/auth.log"
AUTH_LOG_PATH = "logs/sample/auth.log"
EVE_JSON_PATH = "logs/suricata/eve.json"
ES_HOST         = "http://localhost:9200"
ES_INDEX_PREFIX = "siem-logs" 
# Ngưỡng phát hiện
BRUTE_FORCE_THRESHOLD = 5 # số lần thất bại
BRUTE_FORCE_WINDOW = 60 # giây
PORT_SCAN_THRESHOLD = 20 # số cổng khác nhau
PORT_SCAN_WINDOW = 30 # giây
CORRELATION_WINDOW = 900 # 15 phút = 900 giây