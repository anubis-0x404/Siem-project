import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from elasticsearch import Elasticsearch
from config.settings import ES_HOST, ES_INDEX_PREFIX

TEMPLATE_BODY = {
    "index_patterns": [f"{ES_INDEX_PREFIX}-*"],   # khớp đúng prefix dùng trong storage.py (siem-logs-*)
    "priority": 1,
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
        },
        "mappings": {
            "properties": {
                # Thời gian
                "@timestamp": {
                    "type": "date",
                    "format": "yyyy-MM-dd'T'HH:mm:ss||epoch_millis"
                },
                # Thông tin mạng
                "source": {
                    "properties": {
                        "ip":   { "type": "ip" },
                        "port": { "type": "integer" }
                    }
                },
                "destination": {
                    "properties": {
                        "ip":   { "type": "ip" },
                        "port": { "type": "integer" }
                    }
                },
                "network": {
                    "properties": {
                        "protocol": { "type": "keyword" }
                    }
                },
                "event": {
                    "properties": {
                        "kind":           { "type": "keyword" },
                        "category":       { "type": "keyword" },
                        "outcome":        { "type": "keyword" },
                        "severity_label": { "type": "keyword" },
                        "type":           { "type": "keyword" }
                    }
                },
                # Người dùng
                "user": {
                    "properties": {
                        "name": { "type": "keyword" }
                    }
                },
                # Rule phát hiện
                "rule": {
                    "properties": {
                        "name":     { "type": "keyword" },
                        "category": { "type": "keyword" }
                    }
                },
                # Log gốc
                "log": {
                    "properties": {
                        "original": { "type": "text" }   # text để full-text search
                    }
                },
                # Metadata hệ thống
                "tags":        { "type": "keyword" },
                "data_source": { "type": "keyword" },
                "line_number": { "type": "integer" }
            }
        }
    }
}

def create_index_template(es: Elasticsearch) -> bool:
    """Tạo (hoặc cập nhật) index template trên Elasticsearch."""
    try:
        existed_before = es.indices.exists_index_template(name="logs-template").body

        es.indices.put_index_template(
            name="logs-template",
            index_patterns=TEMPLATE_BODY["index_patterns"],
            priority=TEMPLATE_BODY["priority"],
            template=TEMPLATE_BODY["template"]
        )

        if existed_before:
            print("[+] Cập nhật index template thành công (template đã tồn tại trước đó)")
        else:
            print("[+] Tạo index template mới thành công")
        return True

    except Exception as e:
        print(f"[ERROR] Tạo template thất bại: {e}")
        return False

def check_legacy_indices(es: Elasticsearch) -> list[str]:
    bad_indices = []
    try:
        existing = es.indices.get(index=f"{ES_INDEX_PREFIX}-*", ignore_unavailable=True)
    except Exception as e:
        print(f"[ERROR] Không lấy được danh sách index: {e}")
        return bad_indices

    for index_name, index_info in existing.items():
        mapping = (
            index_info.get("mappings", {})
            .get("properties", {})
            .get("source", {})
            .get("properties", {})
            .get("ip", {})
        )
        field_type = mapping.get("type")
        if field_type and field_type != "ip":
            bad_indices.append(index_name)

    if bad_indices:
        print(f"[WARN] Phát hiện {len(bad_indices)} index cũ có mapping source.ip SAI "
              f"(không phải type 'ip'): {bad_indices}")
        print("[WARN] Template KHÔNG retroactive — cần reindex các index này ")
    else:
        print("[+] Không có index cũ nào bị mapping sai cho source.ip")

    return bad_indices

if __name__ == "__main__":
    es = Elasticsearch(ES_HOST)
    if not es.ping():
        print(f"[ERROR] Không kết nối được Elasticsearch tại {ES_HOST}")
        sys.exit(1)

    print(f"[+] Kết nối ES thành công: {ES_HOST}")
    create_index_template(es)
    check_legacy_indices(es)