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

import yaml
import os

# Đọc suricata.yaml
_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_suri_cfg_path = os.path.join(_BASE, "config", "suricata.yaml")

with open(_suri_cfg_path, "r") as f:
    _suri_cfg = yaml.safe_load(f)

# Export để các module import
EVE_JSON_PATH = _suri_cfg["suricata"]["eve_json_path"]
SEVERITY_MAP  = {int(k): v for k, v in _suri_cfg["severity_map"].items()}