# Kibana Setup

## 1. Data Views
- Tạo Data View "SIEM Logs": index pattern `siem-logs-*`, timestamp `@timestamp`
- Tạo Data View "SIEM Alerts": index pattern `siem-alerts-*`, timestamp `@timestamp`

## 2. Visualizations (Lens)
| Tên | Type | Data view | Field chính |
|---|---|---|---|
| Alert List | Table | SIEM Alerts | alert.type, source.ip, alert.severity |
| Alert Timeline | Line | SIEM Alerts | @timestamp / alert.severity |
| Top Attacker IPs | Pie | SIEM Alerts | source.ip.keyword (top 10) |
| Attack Types | Bar vertical | SIEM Alerts | alert.type / alert.severity |

Mỗi visualization: Save → "None" → tick "Add to library"

## 3. Dashboard
Dashboard → Create → Add from library → chọn 4 visualization trên
Tên: "SIEM Mini — Security Overview"
Time range: Last 24 hours, Auto refresh: 10s

## 4. Kiểm tra realtime
Chạy: python3 module4_detection/engine.py --schedule
Dashboard phải tự cập nhật mỗi 10 giây khi có alert mới.