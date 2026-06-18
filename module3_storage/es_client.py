import sys
import os
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from datetime import datetime
from elasticsearch import Elasticsearch, helpers
from config.settings import ES_HOST, ES_INDEX_PREFIX

def connect_elasticsearch() -> Elasticsearch | None:
    try:
        es = Elasticsearch(
            ES_HOST,
            verify_certs=False,
            ssl_show_warn=False,
            retry_on_timeout=True,
            max_retries=3
        )
        if es.ping():
            print(f"[+] Kết nối Elasticsearch thành công: {ES_HOST}")
            return es
        else:
            print(f"[ERROR] Elasticsearch không phản hồi tại {ES_HOST}")
            return None
    except Exception as e:
        print(f"[ERROR] Lỗi kết nối: {e}")
        return None

def ensure_template_exists(es: Elasticsearch) -> bool:
    try:
        if es.indices.exists_index_template(name="logs-template").body:
            return True

        print("[WARN] Template 'logs-template' chưa tồn tại, đang tự tạo trước khi ghi log...")
        from module3_storage.index_template import create_index_template
        return create_index_template(es)

    except Exception as e:
        print(f"[ERROR] Không kiểm tra/tạo được template: {e}")
        return False
    
def get_index_name(timestamp: str = None) -> str:
    if timestamp:
        try:
            dt = datetime.strptime(timestamp[:10], "%Y-%m-%d")
            return f"{ES_INDEX_PREFIX}-{dt.strftime('%Y.%m.%d')}"
        except Exception:
            pass
    return f"{ES_INDEX_PREFIX}-{datetime.now().strftime('%Y.%m.%d')}"

#Luu 1 doc
def index_document(es: Elasticsearch, document: dict) -> bool:
    if not es or not document:
        return False

    try:
        index_name = get_index_name(document.get("@timestamp"))

        es.index(
            index=index_name,
            document=document,
            refresh=False
        )
        return True

    except Exception as e:
        print(f"[ERROR] Lưu document thất bại: {e}")
        return False

#luu nhieu doc cung 1 luc 
def bulk_index_documents(es: Elasticsearch,
                          documents: list[dict]) -> tuple[int, int]:
    if not es or not documents:
        return 0, 0
    # Chuẩn bị hành động cho bulk API
    actions = [
        {
            "_index": get_index_name(doc.get("@timestamp")),
            "_source": doc
        }
        for doc in documents
    ]
    try:
        success, errors = helpers.bulk(
            es,
            actions,
            chunk_size=500,
            raise_on_error=False
        )
        if errors:
            print(f"[WARN] Bulk index: {success} thành công, "
                  f"{len(errors)} thất bại")
        return success, len(errors) if errors else 0

    except Exception as e:
        print(f"[ERROR] Bulk index thất bại: {e}")
        return 0, len(documents)

#Truy van event trong khoang tgian
def query_recent_events(es: Elasticsearch,
                         src_ip: str = None,
                         minutes: int = 60,
                         event_type: str = None) -> list[dict]:
    if not es:
        return []

    must_conditions = [
        {
            "range": {
                "@timestamp": {
                    "gte": f"now-{minutes}m",
                    "lte": "now"
                }
            }
        }
    ]

    if src_ip:
        must_conditions.append({
            "term": {"source.ip": src_ip}
        })

    if event_type:
        must_conditions.append({
            "term": {"event.type": event_type}
        })

    query = {
        "query": {
            "bool": {"must": must_conditions}
        },
        "sort": [
            {"@timestamp": {"order": "desc"}}
        ],
        "size": 1000
    }

    try:
        response = es.search(
            index=f"{ES_INDEX_PREFIX}-*",
            body=query
        )
        return [hit["_source"] for hit in response["hits"]["hits"]]

    except Exception as e:
        print(f"[ERROR] Query thất bại: {e}")
        return []

def count_failed_events(es: Elasticsearch,
                         src_ip: str,
                         seconds: int = 60,
                         event_type: str = None) -> int:
    if not es:
        return 0

    must_conditions = [
        {"term":  {"source.ip":     src_ip}},
        {"term":  {"event.outcome": "failure"}},
        {"range": {"@timestamp": {"gte": f"now-{seconds}s"}}}
    ]

    if event_type:
        must_conditions.append({"term": {"event.type": event_type}})

    query = {
        "query": {
            "bool": {"must": must_conditions}
        }
    }

    try:
        response = es.count(
            index=f"{ES_INDEX_PREFIX}-*",
            body=query
        )
        return response["count"]

    except Exception as e:
        print(f"[ERROR] Count thất bại: {e}")
        return 0
    
if __name__ == "__main__":
    from module2_parser.auth_parser     import parse_auth_log
    from module2_parser.suricata_parser import parse_eve_json
    from module2_parser.normalizer      import normalize
    from config.settings import AUTH_LOG_PATH, EVE_JSON_PATH

    # 1. Kết nối ES
    es = connect_elasticsearch()
    if not es:
        sys.exit(1)
    if not ensure_template_exists(es):
        print("[ERROR] Không đảm bảo được template, dừng để tránh tạo index với mapping sai.")
        sys.exit(1)

    # 2. Parse + normalize auth log
    print("\n[*] Đang xử lý auth.log...")
    auth_raw  = parse_auth_log(AUTH_LOG_PATH)
    auth_docs = [normalize(r) for r in auth_raw if normalize(r)]

    # 3. Parse + normalize suricata log
    print("[*] Đang xử lý eve.json...")
    suri_raw  = parse_eve_json(EVE_JSON_PATH)
    suri_docs = [normalize(r) for r in suri_raw if normalize(r)]

    all_docs = auth_docs + suri_docs
    print(f"[*] Tổng document cần lưu: {len(all_docs)}")

    # 4. Bulk index
    success, failed = bulk_index_documents(es, all_docs)
    print(f"[+] Lưu thành công: {success} | Thất bại: {failed}")

    # 5. Truy vấn kiểm tra
    print("\n[*] Truy vấn lại từ Elasticsearch...")
    import time
    time.sleep(2)  # Chờ ES index xong

    events = query_recent_events(es, minutes=43200)  # 30 ngày
    print(f"[+] Tìm thấy {len(events)} event trong 30 ngày qua")

    for ev in events[:3]:
        print(json.dumps(ev, indent=2, ensure_ascii=False))
        print("-" * 50)