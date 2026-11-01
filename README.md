# Network Traffic Processing Engine & Snort Rule IDS/IPS

Hệ thống thu thập, phân tích gói tin, giải mã payload, quản lý luồng kết nối và so khớp signature Snort phục vụ hệ thống phát hiện và ngăn chặn xâm nhập (Intrusion Detection & Prevention System - IDS/IPS).

## 1. Giới thiệu

Project triển khai engine xử lý lưu lượng mạng và phát hiện xâm nhập cốt lõi cho hệ thống IDS/IPS bằng Python. Hệ thống được thiết kế theo kiến trúc đường ống xử lý tuần tự (modular pipeline), tiếp nhận luồng gói tin thô, chuyển hóa thành các bản ghi sự kiện chuẩn hóa (`Normalized IDS Event`), duy trì ngữ cảnh luồng kết nối (`Flow Context`) và so khớp với tập luật Snort (`Snort Rules`) để sinh ra các cảnh báo phát hiện xâm nhập (`Detection Event`).

Hệ thống được tổ chức thành ba phân hệ chính:

* **Phân hệ 1 - Packet Capture & Protocol Parser**: Thu thập gói tin từ Live Interface hoặc file PCAP; giải mã các tầng mạng IPv4, tầng giao vận (TCP/UDP); nhận diện và bóc tách giao thức tầng ứng dụng (HTTP/1.x, DNS, SMTP).
* **Phân hệ 2 - Decoder, Preprocessor & Flow Tracker**:
  * **Payload Decoder**: Tự động nhận diện và giải mã các dạng biểu diễn như URL percent-encoding, form-urlencoded, HTML entities, SMTP MIME (Base64/Quoted-Printable), cùng cơ chế xử lý an toàn byte nhị phân không hợp lệ.
  * **Data Preprocessor**: Kiểm định tính hợp lệ của dữ liệu (validation), chuẩn hóa định dạng (normalization domain, URI path, headers, timestamp), xử lý dữ liệu khuyết thiếu và gắn nhãn metadata trạng thái.
  * **Flow / Connection Tracker**: Quản lý phiên kết nối theo canonical 5-tuple hai chiều, bám sát vòng đời trạng thái TCP (handshake, established, closing, closed/reset), gom nhóm phiên UDP, cơ chế dọn dẹp flow quá hạn (idle timeout eviction) và trích xuất bộ đặc trưng thống kê lưu lượng.
* **Phân hệ 3 - Core Engine & Snort Rule Matching**:
  * **Rule Loader**: Nạp các tệp luật Snort `.rules`, lọc bỏ chú thích và dòng trống, hỗ trợ bật/tắt luật hoặc tệp luật linh hoạt qua cấu hình.
  * **Rule Parser & Validator**: Phân tích cú pháp rule header và rule options, chuẩn hóa thành Internal Rule Object, phân loại trạng thái `valid` / `invalid` / `unsupported` với lý do cụ thể, đảm bảo hệ thống không dừng đột ngột khi gặp rule lỗi.
  * **Rule Repository / Indexer**: Lưu trữ các rule hợp lệ và lập chỉ mục tối ưu theo giao thức (`TCP`, `UDP`, `IP`) và cổng mạng (`src_port`, `dst_port`), tra cứu nhanh theo SID.
  * **Rule Matching Engine**: So khớp đa tầng: Header (IP, port, CIDR, port range, direction `->` và `<>`), Flow state/direction (`to_server`, `to_client`, `established`, `not_established`), Content (hỗ trợ `nocase`, `offset`, `depth`, `distance`, `within`) và Packet/TCP (`flags`, `dsize`). Cơ chế short-circuit loại bỏ luật không khớp ngay từ header trước khi quét content.
  * **Rule Evaluation Engine**: Tiếp nhận event + flow context, truy vấn Indexer để lấy candidate rules, gọi Matching Engine, hỗ trợ một sự kiện khớp đồng thời $\ge 2$ rule mà không ngắt sớm, theo dõi chỉ số hiệu năng (`events_evaluated`, `candidate_rules_evaluated`, `matches_count`).
  * **Detection Event Generator**: Đóng gói kết quả khớp thành đối tượng `Detection Event` chuẩn hóa, chứa đầy đủ metadata phục vụ module Alert / Logging / Response.

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
     |    - HTTP/1.x, DNS, SMTP Parser       |
     |    - Unknown Payload Fallback         |
     +---------------------------------------+
                         |
                         v
     +---------------------------------------+
     | 4. Payload Decoder                    |
     |    - URL / Percent & Form Decoding    |
     |    - HTML Entity Decoding             |
     |    - MIME Base64 & Quoted-Printable   |
     +---------------------------------------+
                         |
                         v
     +---------------------------------------+
     | 5. Data Preprocessor                  |
     |    - Validation & Normalization       |
     +---------------------------------------+
                         |
                         v
     +---------------------------------------+
     | 6. Flow / Connection Tracker          |
     |    - Bidirectional 5-Tuple            |
     |    - TCP State Machine & UDP Session  |
     |    - Flow Statistics Engine           |
     +---------------------------------------+
                         |
                         v
             [ Normalized IDS Event ]
                         |
                         +-----------------------------------+
                         |                                   |
                         v                                   v
             [ JSON Lines (.jsonl) ]             [ Flow Context (Flow) ]
                                                             |
                                                             v
                         +-------------------------------------------------------+
                         | 7. Rule Evaluation Engine                             |
                         |    - Nhận Normalized Event + Flow Context             |
                         +-------------------------------------------------------+
                                                     |
                                                     v (Truy vấn candidate rules)
                         +-------------------------------------------------------+
                         | 8. Rule Repository / Indexer                          |
                         |    - Index theo Protocol (TCP/UDP/IP) và Port         |
                         |    - Tra cứu nhanh theo SID                           |
                         +-------------------------------------------------------+
                                                     |
                                                     v (Đánh giá từng candidate)
                         +-------------------------------------------------------+
                         | 9. Rule Matching Engine                               |
                         |    [1] Header Match (IP, Port, Direction ->, <>)      |
                         |        |-- (Nếu lệch: loại trước content matching)    |
                         |    [2] Flow Match (to_server, established, ...)       |
                         |    [3] Packet/TCP Match (flags, dsize)                |
                         |    [4] Content Match (nocase, offset, depth, ...)     |
                         |    [5] Relative Match (distance, within)              |
                         +-------------------------------------------------------+
                                                     |
                                                     v (Khi rule thỏa mãn)
                         +-------------------------------------------------------+
                         | 10. Detection Event Generator                         |
                         |     - Trích xuất 5-Tuple, SID, REV, MSG, Priority    |
                         |     - Gán Flow ID, Application Protocol, Match Info   |
                         +-------------------------------------------------------+
                                                     |
                                                     v
                                            [ Detection Event ]
                                                     |
                                                     v
                                           [ JSON Lines (.jsonl) ]
```

## 3. Các tính năng và phạm vi hỗ trợ

### Tầng mạng & giao vận (Network & Transport Layer)
* IPv4 (kiểm tra header length, checksum, địa chỉ nguồn/đích).
* TCP (bóc tách cờ SYN, ACK, FIN, RST, PSH, sequence/ack number, payload).
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
* Tính toán bộ chỉ số thống kê: tổng số gói/byte, số gói/byte theo chiều forward/backward, số lượng cờ TCP (SYN, ACK, FIN, RST) và thời lượng kết nối.

### Phân hệ Core Engine & Snort Rule Matching
* **Header Matching**:
  * Actions: `alert`, `log`, `pass`, `drop`, `reject`.
  * Protocols: `tcp`, `udp`, `ip`.
  * IP/CIDR: `any`, địa chỉ IPv4 đơn lẻ, dải mạng CIDR (`192.168.1.0/24`).
  * Port / Port Ranges: `any`, cổng đơn lẻ, dải cổng mở (`:1024`, `1024:`, `1024:65535`).
  * Directions: Chiều một hướng (`->`) và hai chiều (`<>`).
* **Rule Identification & Classification**:
  * `sid`, `rev`, `msg`, `classtype`, `priority`.
* **Flow / Connection State Matching**:
  * `flow: to_server, to_client, established, not_established`.
* **Packet / TCP Inspection**:
  * `flags`: Khớp chính xác, toán tử `+` (chứa cờ), `*` (bất kỳ), `!` (phủ định), `0` (không cờ).
  * `dsize`: Kích thước payload chính xác, bất đẳng thức (`>`, `<`, `>=`, `<=`, `!`), dải kích thước (`low<>high`).
* **Payload Content Matching**:
  * Chuỗi ký tự ASCII và mã byte hex Snort (`|XX XX|`).
  * `nocase`: Tìm kiếm không phân biệt hoa thường.
  * `offset` & `depth`: Giới hạn vùng tìm kiếm payload tuyệt đối.
  * `distance` & `within`: Giới hạn vùng tìm kiếm tương đối sau pattern trước đó.
* **Xử lý luật ngoài phạm vi**:
  * Tự động nhận diện và gán nhãn `unsupported` đối với keyword ngoài phạm vi (như `pcre`, `byte_test`, `byte_jump`, `fast_pattern`, `threshold`, `icmp`), đảm bảo engine tiếp tục vận hành an toàn.

## 4. Cấu trúc project

```text
.
├── main.py                          # Điểm thực thi chính của pipeline
├── requirements.txt                 # Danh sách thư viện phụ thuộc
├── README.md                        # Tài liệu kỹ thuật hệ thống
├── .gitignore
│
├── ids_parser/                      # Package mã nguồn Parser & Preprocessor & Flow Tracker
│   ├── capture.py                   # Thu thập packet từ PCAP / Live Interface
│   ├── parser.py                    # Parser IPv4 và TCP/UDP
│   ├── models.py                    # Cấu trúc dữ liệu NormalizedEvent và metadata
│   ├── normalizer.py                # Chuẩn hóa dữ liệu thô ban đầu
│   ├── protocols.py                 # Nhận diện giao thức tầng ứng dụng
│   ├── http_parser.py               # Parser giao thức HTTP/1.x
│   ├── dns_parser.py                # Parser giao thức DNS
│   ├── smtp_parser.py               # Parser giao thức SMTP
│   ├── decoder.py                   # Phân hệ Decoder (URL, HTML, MIME, Safe Bytes)
│   ├── preprocessor.py              # Phân hệ Preprocessor (Validation, Normalization)
│   └── flow_tracker.py              # Phân hệ Flow Tracker (State & Statistics)
│
├── ids_rule_engine/                 # Package mã nguồn Core Engine & Rule Matching (Phân hệ 3)
│   ├── models.py                    # Data models: RuleHeader, RuleOption, SnortRule, DetectionEvent
│   ├── loader.py                    # Rule Loader (đọc file, bỏ comment, enable/disable)
│   ├── parser.py                    # Rule Parser & Validator (phân loại valid, invalid, unsupported)
│   ├── indexer.py                   # Rule Repository & Indexer (chỉ mục theo protocol/port, lookup SID)
│   ├── matcher.py                   # Rule Matching Engine (Header, Flow, Packet, Content, Relative)
│   ├── evaluator.py                 # Rule Evaluation Engine (quản lý pipeline đánh giá và thống kê)
│   └── generator.py                 # Detection Event Generator (đóng gói Detection Event chuẩn hóa)
│
├── tests/                           # Thư mục kiểm thử tự động
│   ├── EXERCISE-1/                  # Test suite phân hệ Packet Capture & Parser
│   ├── EXERCISE-2/                  # Test suite phân hệ Decoder, Preprocessor & Flow Tracker
│   └── EXERCISE-3/                  # Test suite phân hệ Core Engine & Snort Rule Matching (Case 1 - 14)
│       ├── test_rule_loader.py      # Case 1: Nạp file luật, bỏ comment và dòng trống
│       ├── test_rule_parser.py      # Case 2, 3, 4: Cú pháp, keyword unsupported, header parsing
│       ├── test_rule_matcher.py     # Case 5: Direction -> và <>
│       ├── test_rule_indexer.py     # Case 6: Indexer IP, TCP, UDP và any
│       ├── test_header_filter.py    # Case 7: Lọc header trước content matching
│       ├── test_flow_matching.py    # Case 8: So khớp flow:to_server, established
│       ├── test_content_nocase.py   # Case 9: Content matching có/không có nocase
│       ├── test_offset_depth.py     # Case 10: Giới hạn vị trí offset / depth
│       ├── test_distance_within.py  # Case 11: Relative content matching distance / within
│       ├── test_flags_dsize.py      # Case 12: So khớp TCP flags và dsize
│       ├── test_multi_match.py      # Case 13: Đánh giá một event khớp đồng thời >= 2 rule
│       ├── test_detection_event.py  # Case 14: Kiểm tra định dạng đầu ra Detection Event
│       └── generate_*.py            # Các script sinh PCAP kiểm thử tương ứng
│
└── TEST/                            # Môi trường lưu trữ rules, pcap và kết quả thực tế
    ├── EXERCISE-1/
    ├── EXERCISE-2/
    └── EXERCISE-3/                  # Dữ liệu kiểm thử của Phân hệ 3
        ├── rules/                   # Tập Snort rules cho từng testcase (case01 - case14)
        ├── pcap/                    # File PCAP mẫu kiểm thử (case05, case07 - case14)
        └── result/                  # Kết quả kiểm thử định dạng JSON Lines (.jsonl)
            ├── case01_loader.jsonl
            ├── case02_syntax_error.jsonl
            ├── case03_unsupported.jsonl
            ├── case04_headers.jsonl
            ├── case05_direction.jsonl
            ├── case06_indexer.jsonl
            ├── case07_header_filter.jsonl
            ├── case08_flow.jsonl
            ├── case09_content_nocase.jsonl
            ├── case10_offset_depth.jsonl
            ├── case11_distance_within.jsonl
            ├── case12_flags_dsize.jsonl
            ├── case13_multi_match.jsonl
            └── case14_detection_event.jsonl
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

## 7. Thực thi hệ thống Live Capture

Bắt gói tin trực tiếp trên interface loopback (`lo`):

```bash
sudo .venv/bin/python main.py \
    --interface lo \
    --count 20 \
    --output TEST/result/live.jsonl
```

Kết hợp bộ lọc BPF (Berkeley Packet Filter):

```bash
sudo .venv/bin/python main.py \
    --interface lo \
    --filter "tcp port 8080" \
    --count 20 \
    --output TEST/result/live_http.jsonl
```

## 8. Sử dụng Core Engine & Rule Matching (Phân hệ 3)

Khởi tạo và thực thi quy trình phát hiện xâm nhập từ mã nguồn Python:

```python
from pathlib import Path
from ids_parser.flow_tracker import FlowTracker
from ids_rule_engine.evaluator import RuleEvaluationEngine
from ids_rule_engine.loader import RuleLoader
from ids_rule_engine.matcher import RuleMatcher
from ids_rule_engine.parser import RuleParser

# 1. Nạp và phân tích cú pháp bộ luật Snort
loader = RuleLoader()
parser = RuleParser()
raw_rules = loader.load_file(Path("TEST/EXERCISE-3/rules/case14_detection_event.rules"))
rules = parser.parse_rules(raw_rules)

# 2. Khởi tạo Engine đánh giá và Flow Tracker
tracker = FlowTracker()
matcher = RuleMatcher()
engine = RuleEvaluationEngine(rules=rules, matcher=matcher, flow_tracker=tracker)

# 3. Đánh giá sự kiện mạng chuẩn hóa (event: NormalizedEvent)
# alerts: list[DetectionEvent]
alerts = engine.evaluate_event(event)
for alert in alerts:
    print(alert.to_dict())
```

## 9. Cấu trúc dữ liệu đầu ra

### 9.1. Normalized IDS Event (Phân hệ 1 & 2)

```json
{
  "packet_id": 1,
  "timestamp": 1700000000.0,
  "src_ip": "10.0.0.5",
  "dst_ip": "192.168.1.20",
  "network_protocol": "IPv4",
  "transport_protocol": "TCP",
  "src_port": 52133,
  "dst_port": 80,
  "tcp_flags": "PA",
  "application_protocol": "HTTP",
  "application_data": {
    "message_type": "request",
    "method": "GET",
    "target": "/../../etc/passwd"
  },
  "payload_b64": "...",
  "parser_status": "ok",
  "flow_id": "TCP_10.0.0.5:52133_192.168.1.20:80",
  "flow_state": "ESTABLISHED",
  "flow_direction": "forward",
  "preprocess_status": "valid",
  "processing_action": "keep",
  "reason": null
}
```

### 9.2. Detection Event (Phân hệ 3)

Mỗi khi sự kiện khớp với signature Snort, `DetectionEventGenerator` sẽ sinh đối tượng cảnh báo với đầy đủ các trường thông tin chuẩn hóa:

```json
{
  "timestamp": 1700000000.0,
  "sid": 140001,
  "rev": 1,
  "msg": "Directory traversal detected",
  "src_ip": "10.0.0.5",
  "src_port": 52133,
  "dst_ip": "192.168.1.20",
  "dst_port": 80,
  "protocol": "TCP",
  "priority": 1,
  "classtype": "web-application-attack",
  "application_protocol": "HTTP",
  "flow_id": "TCP_10.0.0.5:52133_192.168.1.20:80",
  "matched_info": "content=\"../\""
}
```

## 10. Kiểm thử hệ thống

Chạy toàn bộ test suite tự động của hệ thống (bao gồm cả 3 phân hệ):

```bash
PYTHONPATH=. .venv/bin/pytest -v
```
> Kết quả: **119/119 test cases PASSED** (100%).

Chạy kiểm thử riêng theo từng phân hệ:

* **Phân hệ 1** (Packet Capture & Protocol Parser):
```bash
PYTHONPATH=. .venv/bin/pytest tests/EXERCISE-1/ -v
```

* **Phân hệ 2** (Decoder, Preprocessor & Flow Tracker):
```bash
PYTHONPATH=. .venv/bin/pytest tests/EXERCISE-2/ -v
```

* **Phân hệ 3** (Core Engine & Snort Rule Matching):
```bash
PYTHONPATH=. .venv/bin/pytest tests/EXERCISE-3/ -v
```

### Bảng tổng hợp 14 Test Cases bắt buộc của Bài tập 3

| STT | Kịch bản kiểm thử | Mô tả & Trọng tâm kiểm thử | Kết quả mong đợi | Trạng thái |
| :---: | :--- | :--- | :--- | :---: |
| **01** | Rule Loader | Đọc file `.rules`, bỏ qua comment (`#`) và dòng trống, kiểm tra cờ enable/disable | Chỉ rule hợp lệ được đưa sang parser | **PASSED** |
| **02** | Syntax Validator | Kiểm tra rule thiếu ngoặc, thiếu semicolon, sai dải cổng, thiếu `sid` | Đánh dấu `invalid`, có lý do, engine không dừng | **PASSED** |
| **03** | Unsupported Keywords | Kiểm tra keyword ngoài phạm vi (`pcre`, `byte_test`, `byte_jump`, `icmp`) | Đánh dấu `unsupported`, ghi rõ lý do, không crash | **PASSED** |
| **04** | Header Parsing | Phân tích TCP/UDP/IP, `any`, địa chỉ IP, dải CIDR, cổng đơn và port range | Tạo Internal Rule Object chính xác | **PASSED** |
| **05** | Direction Match | So khớp hướng lưu lượng một chiều (`->`) và hai chiều (`<>`) | Khớp chuẩn xác theo chiều gói tin | **PASSED** |
| **06** | Rule Indexer | Lập chỉ mục candidate rules theo giao thức (TCP, UDP, IP) và port | Trả về tập candidate rules chính xác | **PASSED** |
| **07** | Header Filtering | Kiểm tra điều kiện loại trừ sớm khi sai IP, sai port hoặc sai direction | Rule bị loại trước khi bước vào content matching | **PASSED** |
| **08** | Flow Matching | Kiểm tra `to_server`, `to_client`, `established`, `not_established` | Khớp đúng theo trạng thái Flow Tracker | **PASSED** |
| **09** | Content nocase | So khớp payload có cờ `nocase` và không có cờ `nocase` | Phân biệt / không phân biệt hoa thường đúng | **PASSED** |
| **10** | Offset & Depth | Giới hạn cửa sổ tìm kiếm với `offset` và `depth` | Chỉ match khi pattern nằm trong vùng chỉ định | **PASSED** |
| **11** | Relative Matching | Chuỗi nhiều content liên kết qua `distance` và `within` | Tính toán đúng khoảng cách tương đối | **PASSED** |
| **12** | Flags & Dsize | So khớp cờ TCP (`S`, `PA`, `*`, `+`, `!`) và kích thước payload `dsize` | Khớp / không khớp đúng theo gói tin | **PASSED** |
| **13** | Multi-rule Match | Một sự kiện mạng thỏa mãn đồng thời $\ge 2$ rule khác nhau | Sinh đầy đủ kết quả match, không early exit | **PASSED** |
| **14** | Detection Event | Kiểm tra toàn diện đầu ra của bộ tạo cảnh báo (`DetectionEvent`) | Đầy đủ sid, msg, priority, 5-tuple, flow, match info | **PASSED** |

## 11. Cơ chế xử lý lỗi và an toàn hệ thống (Error Handling)

Hệ thống được thiết kế với tiêu chí ổn định cao (fault-tolerant), đảm bảo tiếp tục duy trì hoạt động liên tục khi đối mặt với các dạng dữ liệu dị thường:

* Giao thức tầng giao vận hoặc ứng dụng chưa được hỗ trợ.
* Thiếu header tầng mạng IPv4 hoặc packet bị phân mảnh cụt.
* Payload trống hoặc payload ứng dụng không đúng cấu trúc chuẩn.
* Byte nhị phân không thuộc bảng mã UTF-8/ASCII tiêu chuẩn.
* Gói tin chứa thông số bất thường (port vượt dải, timestamp âm, header lỗi).
* Rule Snort bị lỗi cú pháp, thiếu trường bắt buộc hoặc chứa keyword ngoài phạm vi được phân loại rõ ràng thành `invalid` / `unsupported` mà không làm gián đoạn chương trình.

## 12. AI Usage Disclosure

Trong quá trình thực hiện bài tập, AI được sử dụng để hỗ trợ:

* Phân tích yêu cầu và cấu trúc bài tập.
* Gợi ý kiến trúc parsing pipeline và cách tổ chức mã nguồn.
* Giải thích, rà soát và hỗ trợ sửa lỗi trong quá trình phát triển.
* Hỗ trợ xây dựng và kiểm tra các testcase.

Công cụ AI được sử dụng: OpenAI ChatGPT, Google Antigravity (Google Gemini).

Các phần mã nguồn có sử dụng AI hỗ trợ gồm:

* `main.py`
* Các module trong thư mục `ids_parser/`
* Các module trong thư mục `ids_rule_engine/`
* Các test và script tạo PCAP trong thư mục `tests/`
* Nội dung README và một số tài liệu mô tả project.

AI chỉ được sử dụng để hỗ trợ quá trình phát triển và kiểm thử; mã nguồn được kiểm tra, chạy thử và điều chỉnh trong quá trình thực hiện bài tập.
