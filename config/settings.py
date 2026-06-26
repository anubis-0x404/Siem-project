import os
import yaml

AUTH_LOG_PATH = "/var/log/remote/victim-auth.log"
EVE_JSON_PATH = "/var/log/remote/victim-eve.json"

# Cấu hình Suricata bổ sung
_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_suri_cfg_path = os.path.join(_BASE, "config", "suricata.yaml")

if os.path.exists(_suri_cfg_path):
    with open(_suri_cfg_path, "r") as f:
        _suri_cfg = yaml.safe_load(f)
    # EVE_JSON_PATH = _suri_cfg["suricata"]["eve_json_path"]
    SEVERITY_MAP = {int(k): v for k, v in _suri_cfg["severity_map"].items()}
else:
    SEVERITY_MAP = {1: "high", 2: "medium", 3: "low"}

# Cấu hình Elasticsearch
ES_HOST = "http://localhost:9200"
ES_INDEX_PREFIX = "siem-logs"

# Ngưỡng phát hiện
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 60
PORT_SCAN_THRESHOLD = 20
PORT_SCAN_WINDOW = 30
CORRELATION_WINDOW = 900