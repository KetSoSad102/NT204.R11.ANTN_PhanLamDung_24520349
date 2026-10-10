from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP

from ids_parser.protocols import detect_application_protocol


def test_detect_http_get_on_standard_port() -> None:
    packet = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=12345, dport=80)
        / b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )

    result = detect_application_protocol(
        packet,
        transport_protocol="TCP",
        src_port=12345,
        dst_port=80,
        payload=bytes(packet[TCP].payload),
    )

    assert result == "HTTP"


def test_detect_http_on_non_standard_port() -> None:
    packet = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=12345, dport=8080)
        / b"GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )

    result = detect_application_protocol(
        packet,
        transport_protocol="TCP",
        src_port=12345,
        dst_port=8080,
        payload=bytes(packet[TCP].payload),
    )

    assert result == "HTTP"


def test_detect_http_response() -> None:
    packet = (
        IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=80, dport=12345)
        / b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    )

    result = detect_application_protocol(
        packet,
        transport_protocol="TCP",
        src_port=80,
        dst_port=12345,
        payload=bytes(packet[TCP].payload),
    )

    assert result == "HTTP"


def test_detect_dns() -> None:
    packet = (
        IP(src="10.0.0.1", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )

    result = detect_application_protocol(
        packet,
        transport_protocol="UDP",
        src_port=53000,
        dst_port=53,
        payload=bytes(packet[UDP].payload),
    )

    assert result == "DNS"


def test_detect_smtp_command() -> None:
    packet = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=50000, dport=25)
        / b"EHLO example.com\r\n"
    )

    result = detect_application_protocol(
        packet,
        transport_protocol="TCP",
        src_port=50000,
        dst_port=25,
        payload=bytes(packet[TCP].payload),
    )

    assert result == "SMTP"


def test_detect_smtp_response() -> None:
    packet = (
        IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=25, dport=50000)
        / b"220 mail.example.com ESMTP\r\n"
    )

    result = detect_application_protocol(
        packet,
        transport_protocol="TCP",
        src_port=25,
        dst_port=50000,
        payload=bytes(packet[TCP].payload),
    )

    assert result == "SMTP"


def test_unknown_protocol() -> None:
    packet = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=40000, dport=4444)
        / b"completely unknown protocol data"
    )

    result = detect_application_protocol(
        packet,
        transport_protocol="TCP",
        src_port=40000,
        dst_port=4444,
        payload=bytes(packet[TCP].payload),
    )

    assert result == "UNKNOWN"
