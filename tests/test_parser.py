from scapy.layers.inet import IP, TCP

from ids_parser.capture import CapturedPacket
from ids_parser.parser import parse_ipv4, parse_tcp


def test_parse_ipv4() -> None:
    packet = IP(
        src="192.168.1.10",
        dst="192.168.1.20",
        ttl=64,
    ) / TCP(
        sport=12345,
        dport=80,
    )

    captured = CapturedPacket(
        packet=packet,
        timestamp=1234567890.0,
    )

    result = parse_ipv4(captured)

    assert result["timestamp"] == 1234567890.0
    assert result["src_ip"] == "192.168.1.10"
    assert result["dst_ip"] == "192.168.1.20"
    assert result["protocol"] == 6
    assert result["ttl"] == 64

def test_parse_tcp() -> None:
    packet = IP(
        src="10.0.0.1",
        dst="10.0.0.2",
    ) / TCP(
        sport=12345,
        dport=80,
        seq=100,
        ack=200,
        flags="PA",
        window=4096,
    ) / b"GET / HTTP/1.1\r\n\r\n"

    captured = CapturedPacket(
        packet=packet,
        timestamp=1234567890.0,
    )

    result = parse_tcp(captured)

    assert result["src_ip"] == "10.0.0.1"
    assert result["dst_ip"] == "10.0.0.2"
    assert result["src_port"] == 12345
    assert result["dst_port"] == 80
    assert result["seq"] == 100
    assert result["ack"] == 200
    assert result["flags"] == "PA"
    assert result["window"] == 4096
    assert result["payload"] == b"GET / HTTP/1.1\r\n\r\n"

def test_tcp_handshake_flags() -> None:
    syn = CapturedPacket(
        packet=IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=12345, dport=80, flags="S"),
        timestamp=1.0,
    )

    syn_ack = CapturedPacket(
        packet=IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=80, dport=12345, flags="SA"),
        timestamp=2.0,
    )

    ack = CapturedPacket(
        packet=IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=12345, dport=80, flags="A"),
        timestamp=3.0,
    )

    assert parse_tcp(syn)["flags"] == "S"
    assert parse_tcp(syn_ack)["flags"] == "SA"
    assert parse_tcp(ack)["flags"] == "A"