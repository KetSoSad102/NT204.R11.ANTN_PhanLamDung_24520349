from scapy.layers.inet import IP, TCP

from ids_parser.capture import CapturedPacket
from ids_parser.parser import parse_ipv4


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
