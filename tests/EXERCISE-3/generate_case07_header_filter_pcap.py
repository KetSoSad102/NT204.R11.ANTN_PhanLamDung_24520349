from __future__ import annotations

from pathlib import Path
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap


def generate_pcap(output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    payload = b"GET /index.html HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\nMALICIOUS_PAYLOAD"

    pkt1 = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=54321, dport=80, flags="PA", seq=1000, ack=2000) / Raw(load=payload)
    pkt1.time = 1700000000.0

    wrpcap(str(output_path), [pkt1])


if __name__ == "__main__":
    pcap_file = Path("TEST/EXERCISE-3/pcap/case07_header_filter.pcap")
    generate_pcap(pcap_file)

