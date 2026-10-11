# Network Traffic Processing Engine for IDS/IPS

Hệ thống thu thập, phân tích gói tin, giải mã payload và quản lý luồng kết nối phục vụ hệ thống phát hiện và ngăn chặn xâm nhập (Intrusion Detection & Prevention System - IDS/IPS).

## 1. Giới thiệu

Project triển khai engine xử lý lưu lượng mạng cốt lõi cho hệ thống IDS/IPS bằng Python. Hệ thống được thiết kế theo kiến trúc đường ống xử lý tuần tự (modular pipeline), tiếp nhận luồng gói tin thô và chuyển hóa thành các bản ghi sự kiện chuẩn hóa (`Normalized IDS Event`) có cấu trúc, sẵn sàng cung cấp cho Feature Extractor và Detection Engine.

Hệ thống được tổ chức thành các phân hệ chính:

* **Phân hệ 1 - Packet Capture & Protocol Parser**: Thu thập gói tin từ Live Interface hoặc file PCAP; giải mã các tầng mạng IPv4, tầng giao vận (TCP/UDP); nhận diện và bóc tách giao thức tầng ứng dụng (HTTP/1.x, DNS, SMTP).
* **Phân hệ 2 - Decoder, Preprocessor & Flow Tracker**:
  * **Payload Decoder**: Tự động nhận diện và giải mã các dạng biểu diễn như URL percent-encoding, form-urlencoded, HTML entities, SMTP MIME (Base64/Quoted-Printable), cùng cơ chế xử lý an toàn byte nhị phân không hợp lệ.
  * **Data Preprocessor**: Kiểm định tính hợp lệ của dữ liệu (validation), chuẩn hóa định dạng (normalization domain, URI path, headers, timestamp), xử lý dữ liệu khuyết thiếu và gắn nhãn metadata trạng thái.
  * **Flow / Connection Tracker**: Quản lý phiên kết nối theo canonical 5-tuple hai chiều, bám sát vòng đời trạng thái TCP (handshake, established, closing, closed/reset), gom nhóm phiên UDP, cơ chế dọn dẹp flow quá hạn (idle timeout eviction) và trích xuất bộ đặc trưng thống kê lưu lượng.

## 2. Kiến trúc hệ thống

```text
       [ PCAP File ]       [ Live Interface ]
             \                    /
              v                  v
     +---------------------------------------+
     | 1. Packet Capture Module              |
     +---------------------------------------+
                         |
                         v
     +---------------------------------------+
     | 2. Network & Transport Parser         |
     |    - IPv4 Header Parsing              |
     |    - TCP / UDP Header Parsing         |
     +---------------------------------------+
                         |
                         v
     +---------------------------------------+
     | 3. Application Protocol Detector      |
     |    - HTTP/1.x Parser                  |
     |    - DNS Parser                       |
     |    - SMTP Parser                      |
     |    - Unknown Payload Fallback         |
     +---------------------------------------+
                         |
                         v
     +---------------------------------------+
     | 4. Payload Decoder                    |
     |    - URL / Percent & Form Decoding    |
     |    - HTML Entity Decoding             |
     |    - MIME Base64 & Quoted-Printable   |
     |    - Safe Byte Sequence Recovery      |
     +---------------------------------------+
                         |
                         v
     +---------------------------------------+
     | 5. Data Preprocessor                  |
     |    - Field & Range Validation         |
     |    - Canonical Normalization          |
     |    - Missing Data Sanitization        |
     |    - Status & Reason Tagging          |
     +---------------------------------------+
                         |
                         v
     +---------------------------------------+
     | 6. Flow / Connection Tracker          |
     |    - Canonical Bidirectional 5-Tuple  |
     |    - TCP State Machine Tracking       |
     |    - UDP Session Grouping             |
     |    - Idle Timeout Garbage Collector   |
     |    - Traffic Statistics Engine        |
     +---------------------------------------+
                         |
                         v
            [ Normalized IDS Event ]
                         |
                         v
              [ JSON Lines (.jsonl) ]
```

Pipeline vận hành khép kín và an toàn: bất kỳ lỗi phát sinh ở tầng ứng dụng hoặc payload hỏng đều được gắn nhãn trạng thái thích hợp trong metadata mà không làm ngắt quãng luồng xử lý toàn cục.

## 3. Các giao thức và tính năng hỗ trợ

### Tầng mạng (Network Layer)

* IPv4 (kiểm tra header length, checksum, địa chỉ nguồn/đích).

### Tầng giao vận (Transport Layer)

* TCP (bóc tách cờ điều khiển SYN, ACK, FIN, RST, PSH, sequence/ack number, payload).
* UDP (bóc tách port, length, checksum, payload).

### Tầng ứng dụng (Application Layer)

* HTTP/1.x: Phân tích request method, URI, headers, status code, response body.
* DNS: Phân tích query ID, flags, domain name, record type (A, AAAA, MX, NS, ...), danh sách câu trả lời.
* SMTP: Nhận diện lệnh (HELO, EHLO, MAIL FROM, RCPT TO, DATA), response code và email body.

### Phân hệ Decoder & Preprocessor

* HTTP URL decoding & `application/x-www-form-urlencoded`.
* HTML entity decoding trong văn bản payload.
* SMTP/MIME Base64 & Quoted-Printable decoding.
* Safe byte/character decoding (ASCII, UTF-8) không crash khi gặp payload nhị phân bất thường.
* Validation: kiểm tra trường bắt buộc, dải port hợp lệ (0-65535), timestamp không âm, giao thức hỗ trợ.
* Normalization: chuẩn hóa tên protocol in hoa, domain và IP chữ thường, chuẩn hóa URI path, header chữ thường.
* Missing/unsupported data: gắn giá trị mặc định nhất quán (`null`, `[]`, `{}`).
* Metadata: bổ sung `preprocess_status`, `processing_action`, và `reason`.

### Phân hệ Flow / Connection Tracker

* Định danh luồng theo Canonical 5-tuple hai chiều (`PROTO_IP1:PORT1_IP2:PORT2`).
* Theo dõi vòng đời kết nối TCP: `NEW/HANDSHAKE` $\rightarrow$ `ESTABLISHED` $\rightarrow$ `CLOSING` $\rightarrow$ `CLOSED/RESET`.
* Gom nhóm gói tin UDP hai chiều thành flow hoàn chỉnh.
* Quản lý nhiều luồng kết nối đồng thời độc lập (concurrent flows isolation).
* Cơ chế tự động giải phóng flow quá hạn (idle timeout eviction).
* Tính toán bộ chỉ số thống kê: tổng số gói/byte, số gói/byte theo chiều forward/backward, số lượng cờ TCP (SYN, ACK, FIN, RST) và thời gian duy trì kết nối (duration).

## 4. Cấu trúc project

```text
.
├── main.py                          # Điểm thực thi chính của pipeline
├── requirements.txt                 # Danh sách thư viện phụ thuộc
├── README.md                        # Tài liệu kỹ thuật hệ thống
├── .gitignore
│
├── ids_parser/                      # Package mã nguồn lõi của engine
│   ├── capture.py                   # Module thu thập packet từ PCAP / Live Interface
│   ├── parser.py                    # Parser tầng mạng IPv4 và tầng giao vận TCP/UDP
│   ├── models.py                    # Cấu trúc dữ liệu NormalizedEvent và metadata
│   ├── normalizer.py                # Chuẩn hóa dữ liệu thô ban đầu
│   ├── protocols.py                 # Engine nhận diện giao thức tầng ứng dụng
│   ├── http_parser.py               # Parser giao thức HTTP/1.x
│   ├── dns_parser.py                # Parser giao thức DNS
│   ├── smtp_parser.py               # Parser giao thức SMTP
│   ├── decoder.py                   # Phân hệ Decoder (URL, HTML, MIME, Safe Bytes)
│   ├── preprocessor.py              # Phân hệ Preprocessor (Validation, Normalization)
│   └── flow_tracker.py              # Phân hệ Flow Tracker (State & Statistics)
│
├── tests/                           # Thư mục kiểm thử tự động
│   ├── EXERCISE-1/                  # Test suite cho phân hệ Packet Capture & Parser
│   │   ├── test_capture.py
│   │   ├── test_parser.py
│   │   ├── test_protocols.py
│   │   ├── test_http_parser.py
│   │   ├── test_dns_parser.py
│   │   ├── test_smtp_parser.py
│   │   └── generate_*.py
│   │
│   └── EXERCISE-2/                  # Test suite cho phân hệ Decoder, Preprocessor & Flow Tracker
│       ├── test_decoder.py          # Kiểm thử chức năng Decoder
│       ├── test_preprocessor.py     # Kiểm thử chức năng Preprocessor & Malformed
│       ├── test_flow_tracker.py     # Kiểm thử chức năng Flow Tracker & Statistics
│       └── generate_t01_*.py ... generate_t14_*.py
│
└── TEST/                            # Môi trường kiểm thử dữ liệu thực tế
    ├── EXERCISE-1/
    │   ├── pcap/                    # File PCAP mẫu kiểm thử phân hệ 1
    │   └── result/                  # Kết quả JSON Lines phân hệ 1
    │
    └── EXERCISE-2/
        ├── pcap/                    # File PCAP kịch bản kiểm thử phân hệ 2
        │   ├── t01_http_url.pcap
        │   ├── t02_html_entity.pcap
        │   ├── t03_smtp_mime.pcap
        │   ├── t04_invalid_bytes.pcap
        │   ├── t05_normalization.pcap
        │   ├── t06_missing_fields.pcap
        │   ├── t07_tcp_handshake.pcap
        │   ├── t08_bidirectional.pcap
        │   ├── t09_tcp_close.pcap
        │   ├── t10_udp_flow.pcap
        │   ├── t11_concurrent_flows.pcap
        │   ├── t12_idle_timeout.pcap
        │   ├── t13_statistics.pcap
        │   └── t14_malformed.pcap
        └── result/                  # Kết quả JSON Lines đầu ra tương ứng
            ├── t01_http_url.jsonl
            ├── t02_html_entity.jsonl
            ├── t03_smtp_mime.jsonl
            ├── t04_invalid_bytes.jsonl
            ├── t05_normalization.jsonl
            ├── t06_missing_fields.jsonl
            ├── t07_tcp_handshake.jsonl
            ├── t08_bidirectional.jsonl
            ├── t09_tcp_close.jsonl
            ├── t10_udp_flow.jsonl
            ├── t11_concurrent_flows.jsonl
            ├── t12_idle_timeout.jsonl
            ├── t13_statistics.jsonl
            └── t14_malformed.jsonl
```

## 5. Cài đặt môi trường

Yêu cầu môi trường Python 3.10 trở lên.

1. Khởi tạo virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Cài đặt các gói phụ thuộc:

```bash
pip install -r requirements.txt
```

## 6. Thực thi hệ thống với PCAP

Xử lý file PCAP qua toàn bộ pipeline phân tích và trích xuất ra JSON Lines:

```bash
python main.py \
    --pcap TEST/EXERCISE-2/pcap/t13_statistics.pcap \
    --output TEST/EXERCISE-2/result/t13_statistics.jsonl
```

Chương trình sẽ tự động duyệt từng packet qua các module Parser $\rightarrow$ Decoder $\rightarrow$ Preprocessor $\rightarrow$ Flow Tracker và ghi kết quả có cấu trúc ra file JSON Lines.

## 7. Thực thi hệ thống Live Capture

Kiểm tra danh sách network interface khả dụng:

```bash
ip -br link
```

Bắt gói tin trực tiếp trên interface loopback (`lo`):

```bash
sudo .venv/bin/python main.py \
    --interface lo \
    --count 20 \
    --output TEST/result/live.jsonl
```

Kết hợp bộ lọc BPF (Berkeley Packet Filter) để giới hạn luồng traffic:

```bash
sudo .venv/bin/python main.py \
    --interface lo \
    --filter "tcp port 8080" \
    --count 20 \
    --output TEST/result/live_http.jsonl
```

## 8. Các tùy chọn dòng lệnh (CLI Options)

```text
--pcap FILE
    Đọc và phân tích gói tin từ file PCAP.

--interface INTERFACE
    Lắng nghe và thu thập gói tin trực tiếp từ network interface.

--output FILE
    Đường dẫn file kết quả đầu ra định dạng JSON Lines (.jsonl).

--count N
    Giới hạn số lượng gói tin tối đa cần xử lý.

--filter FILTER
    Bộ lọc BPF áp dụng khi thực hiện live capture.
```

## 9. Cấu trúc Normalized IDS Event

Mỗi gói tin sau khi hoàn tất pipeline sẽ được chuẩn hóa thành một đối tượng sự kiện duy nhất:

```json
{
  "packet_id": 1,
  "timestamp": 1700000000.0,
  "src_ip": "10.0.0.1",
  "dst_ip": "10.0.0.2",
  "network_protocol": "IPv4",
  "transport_protocol": "TCP",
  "src_port": 50000,
  "dst_port": 80,
  "tcp_flags": "PA",
  "application_protocol": "HTTP",
  "application_data": {
    "message_type": "request",
    "method": "GET",
    "target": "/search",
    "version": "HTTP/1.1",
    "headers": {"host": "example.com"},
    "body": "",
    "raw_uri": "/search?q=%27%20OR%201%3D1",
    "decoded_uri": "/search?q=' OR 1=1"
  },
  "payload_b64": "...",
  "parser_status": "ok",
  "flow_id": "TCP_10.0.0.1:50000_10.0.0.2:80",
  "flow_state": "ESTABLISHED",
  "flow_direction": "forward",
  "preprocess_status": "valid",
  "processing_action": "keep",
  "reason": null
}
```

## 10. Định dạng đầu ra JSON Lines

Mỗi dòng trong file đầu ra tương ứng với một packet event độc lập, đáp ứng tiêu chuẩn xử lý stream và tương thích với các công cụ chấm điểm / trích xuất đặc trưng tự động:

```json
{"packet_id": 1, "timestamp": 1700000000.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", ...}
{"packet_id": 2, "timestamp": 1700000000.1, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", ...}
```

## 11. Kiểm thử hệ thống

Chạy toàn bộ test suite tự động của hệ thống:

```bash
PYTHONPATH=. .venv/bin/pytest -v
```
> Kết quả: **54/54 test cases PASSED** (100%).

Chạy kiểm thử riêng theo từng phân hệ:

* Kiểm thử phân hệ Capture & Parser:
```bash
PYTHONPATH=. .venv/bin/pytest tests/EXERCISE-1/ -v
```

* Kiểm thử phân hệ Decoder, Preprocessor & Flow Tracker:
```bash
PYTHONPATH=. .venv/bin/pytest tests/EXERCISE-2/ -v
```

### Bảng tổng hợp các kịch bản kiểm thử (Test Scenarios T01 - T14)

| Mã | Kịch bản kiểm thử | Trọng tâm kiểm thử | Trạng thái |
| :--- | :--- | :--- | :---: |
| **T01** | HTTP URL decode | Giải mã percent-encoding, bảo toàn `raw_uri` và sinh `decoded_uri` | **PASSED** |
| **T02** | HTML entity decode | Giải mã các ký tự thực thể HTML (`&lt;`, `&gt;`, `&quot;`) trong payload | **PASSED** |
| **T03** | SMTP Base64/QP decode | Nhận diện encoding và giải mã MIME body Base64 / Quoted-Printable | **PASSED** |
| **T04** | Invalid bytes handling | Xử lý an toàn byte sequence không hợp lệ, không crash, gắn cờ `partial` | **PASSED** |
| **T05** | Normalization | Chuẩn hóa protocol in hoa, domain/IP chữ thường, chuẩn hóa URI path | **PASSED** |
| **T06** | Missing fields sanitization | Đảm bảo tính nhất quán của các trường thiếu với default (`null`, `[]`, `{}`) | **PASSED** |
| **T07** | TCP handshake tracking | Theo dõi tiến trình bắt tay 3 bước `NEW/HANDSHAKE` $\rightarrow$ `ESTABLISHED` | **PASSED** |
| **T08** | Bidirectional flow tracking | Ánh xạ gói tin hai chiều về cùng `flow_id`, xác định đúng `forward`/`backward` | **PASSED** |
| **T09** | TCP close state tracking | Cập nhật chuyển trạng thái `CLOSING` $\rightarrow$ `CLOSED/RESET` khi nhận FIN / RST | **PASSED** |
| **T10** | UDP query/response session | Gom nhóm gói tin DNS UDP hai chiều, tích lũy đúng số lượng gói và byte | **PASSED** |
| **T11** | Concurrent flows isolation | Quản lý đồng thời nhiều kết nối độc lập, không nhầm lẫn flow | **PASSED** |
| **T12** | Flow idle timeout eviction | Tự động phát hiện và thu hồi các flow vượt ngưỡng thời gian chờ | **PASSED** |
| **T13** | Flow statistics calculation | Tính toán chính xác bộ đếm gói/byte hai chiều, bộ đếm cờ TCP và thời lượng | **PASSED** |
| **T14** | Malformed event resilience | Xử lý gói tin lỗi an toàn, gán đúng nhãn `status`, `action`, `reason` | **PASSED** |

## 12. Cơ chế xử lý lỗi và an toàn hệ thống (Error Handling)

Hệ thống được thiết kế với tiêu chí ổn định cao (fault-tolerant), đảm bảo tiếp tục duy trì hoạt động liên tục khi đối mặt với các dạng dữ liệu dị thường:

* Giao thức tầng giao vận hoặc ứng dụng chưa được hỗ trợ.
* Thiếu header tầng mạng IPv4 hoặc packet bị phân mảnh cụt.
* Payload trống hoặc payload ứng dụng không đúng cấu trúc chuẩn.
* Byte nhị phân không thuộc bảng mã UTF-8/ASCII tiêu chuẩn.
* Gói tin chứa thông số bất thường (port vượt dải, timestamp âm, header lỗi).
* Lỗi phát sinh trong quá trình decode hoặc parse dữ liệu.

Tất cả các trường hợp trên đều được hệ thống ghi nhận chi tiết vào các trường metadata (`parser_status`, `preprocess_status`, `processing_action`, `reason`) thay vì làm gián đoạn tiến trình đang chạy.

## 13. AI Usage Disclosure

Trong quá trình thực hiện bài tập, AI được sử dụng để hỗ trợ:

* Phân tích yêu cầu và cấu trúc bài tập.
* Gợi ý kiến trúc parsing pipeline và cách tổ chức mã nguồn.
* Giải thích, rà soát và hỗ trợ sửa lỗi trong quá trình phát triển.
* Hỗ trợ xây dựng và kiểm tra các testcase.

Công cụ AI được sử dụng: OpenAI ChatGPT, Google Antigravity (Google Gemini).

Các phần mã nguồn có sử dụng AI hỗ trợ gồm:

* `main.py`
* Các module trong thư mục `ids_parser/`
* Các test và script tạo PCAP trong thư mục `tests/`
* Nội dung README và một số tài liệu mô tả project.

AI chỉ được sử dụng để hỗ trợ quá trình phát triển và kiểm thử; mã nguồn được kiểm tra, chạy thử và điều chỉnh trong quá trình thực hiện bài tập.

