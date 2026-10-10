from pathlib import Path

from scapy.all import IP, TCP, wrpcap

from ids_parser.capture import iter_packets


def test_pcap_capture(tmp_path: Path) -> None:
    pcap_path = tmp_path / "capture.pcap"

    packets = [
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80),
        IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1234),
    ]

    wrpcap(str(pcap_path), packets)

    captured = list(iter_packets(pcap=pcap_path))

    assert len(captured) == 2
    assert captured[0].packet[IP].src == "10.0.0.1"
    assert captured[0].packet[IP].dst == "10.0.0.2"
    assert captured[0].timestamp > 0
