# Packet Capture & Parser for IDS

Hệ thống tìm kiếm, phát hiện và ngăn chặn xâm nhập.

## 1. Giới thiệu

Project xây dựng module Packet Capture & Parser bằng Python cho một hệ thống Intrusion Detection System (IDS).

Module hỗ trợ hai nguồn packet:

* Live traffic từ network interface
* Packet từ file PCAP

Cả hai nguồn đều sử dụng cùng một parsing pipeline và tạo ra cùng một cấu trúc `Normalized IDS Event`.

## 2. Kiến trúc

```text
PCAP / Live Interface
        |
        v
Packet Capture
        |
        v
IPv4 Parser
        |
        v
TCP / UDP Parser
        |
        v
Application Protocol Detection
        |
        +---- HTTP/1.x ----> HTTP Parser
        |
        +---- DNS ---------> DNS Parser
        |
        +---- SMTP --------> SMTP Parser
        |
        +---- UNKNOWN
        |
        v
Normalized IDS Event
        |
        v
JSON Lines (.jsonl)
```

Application protocol detection kết hợp thông tin transport/port với payload signature. HTTP request/response có thể được nhận diện từ payload mà không phụ thuộc tuyệt đối vào port.

## 3. Các protocol hỗ trợ

### Network

* IPv4

### Transport

* TCP
* UDP

### Application

* HTTP/1.x
* DNS
* SMTP

Packet không thuộc protocol được hỗ trợ có thể được đánh dấu `UNKNOWN`. Packet malformed hoặc thiếu header được ghi nhận bằng `parser_status` thay vì làm chương trình dừng.

## 4. Cấu trúc project

```text
.
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── ids_parser/
│   ├── capture.py
│   ├── parser.py
│   ├── models.py
│   ├── normalizer.py
│   ├── protocols.py
│   ├── http_parser.py
│   ├── dns_parser.py
│   └── smtp_parser.py
│
├── tests/
│   ├── test_capture.py
│   ├── test_parser.py
│   ├── test_protocols.py
│   ├── test_http_parser.py
│   ├── test_dns_parser.py
│   ├── test_smtp_parser.py
│   └── generate_*.py
│
└── TEST/
    ├── pcap/
    │   └── *.pcap
    └── result/
        └── *.jsonl
```

## 5. Cài đặt

Yêu cầu Python 3.10 trở lên.

Tạo virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Cài dependency:

```bash
pip install -r requirements.txt
```

## 6. Chạy với PCAP

Ví dụ:

```bash
python main.py \
    --pcap TEST/http_requests.pcap \
    --output TEST/result/events.jsonl
```

Chương trình sẽ đọc packet từ PCAP, chạy qua parsing pipeline và ghi normalized event vào file JSON Lines.

## 7. Live capture

Xem network interface:

```bash
ip -br link
```

Ví dụ capture trên `lo`:

```bash
sudo .venv/bin/python main.py \
    --interface lo \
    --count 20 \
    --output TEST/result/live.jsonl
```

Có thể sử dụng BPF filter để giới hạn traffic:

```bash
sudo .venv/bin/python main.py \
    --interface lo \
    --filter "tcp port 8080" \
    --count 20 \
    --output TEST/result/live_http.jsonl
```

## 8. Command line options

```text
--pcap FILE
    Đọc packet từ file PCAP.

--interface INTERFACE
    Capture packet trực tiếp từ network interface.

--output FILE
    File JSON Lines đầu ra.

--count N
    Giới hạn số packet xử lý trong live capture.

--filter FILTER
    BPF filter cho live capture.
```

`--pcap` và `--interface` là hai nguồn input thay thế cho nhau.

## 9. Normalized IDS Event

Mỗi packet được chuyển thành một normalized event có cấu trúc thống nhất, gồm các trường chính:

```json
{
  "packet_id": 1,
  "timestamp": 1790436866.123,
  "src_ip": "10.0.0.1",
  "dst_ip": "10.0.0.2",
  "network_protocol": "IPv4",
  "transport_protocol": "TCP",
  "src_port": 12345,
  "dst_port": 80,
  "tcp_flags": "PA",
  "application_protocol": "HTTP",
  "application_data": {},
  "payload_b64": "...",
  "parser_status": "ok"
}
```

Payload được lưu dưới dạng Base64 để đảm bảo object có thể serialize thành JSON.

## 10. JSON Lines output

Mỗi dòng trong output tương ứng với một packet/event:

```text
event 1
event 2
event 3
...
```

Ví dụ:

```json
{"packet_id":1,"src_ip":"10.0.0.1","dst_ip":"10.0.0.2", ...}
{"packet_id":2,"src_ip":"10.0.0.2","dst_ip":"10.0.0.1", ...}
```

Output normalized này được thiết kế để các module IDS phía sau có thể sử dụng mà không cần truy cập trực tiếp vào Scapy packet.

## 11. Kiểm thử

Chạy toàn bộ unit test:

```bash
python -m pytest -q
```

Các testcase đã kiểm thử gồm:

* TCP handshake: SYN, SYN/ACK, ACK
* TCP data
* UDP
* HTTP GET
* HTTP POST
* HTTP response
* DNS Query
* DNS Response
* SMTP command
* SMTP response
* Unknown protocol
* Malformed packet
* Live packet capture
* Live HTTP capture

Kết quả kiểm thử được lưu trong thư mục:

```text
TEST/
```

Các file PCAP được tạo bằng Scapy và sau đó được đưa qua `main.py` để kiểm tra integration pipeline.

## 12. Error handling

Chương trình cố gắng tiếp tục xử lý khi gặp:

* Unsupported transport/application protocol
* Missing IPv4 header
* Empty payload
* Malformed protocol payload
* Parser error

Các lỗi được ghi nhận trong trường `parser_status` thay vì làm toàn bộ pipeline dừng.

## 13. AI Usage Disclosure

Trong quá trình thực hiện bài tập, AI được sử dụng để:

* Hỗ trợ phân tích yêu cầu bài tập.
* Gợi ý kiến trúc parsing pipeline.
* Hỗ trợ giải thích và rà soát code.
* Hỗ trợ xây dựng và kiểm tra các testcase.
* Hỗ trợ phát hiện và sửa một số lỗi trong quá trình phát triển.

Công cụ AI được sử dụng: OpenAI ChatGPT.