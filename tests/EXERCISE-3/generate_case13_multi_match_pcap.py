from __future__ import annotations

from pathlib import Path
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap


def generate_pcap(output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    src_ip = "192.168.1.100"
    dst_ip = "10.0.0.1"

    payload1 = b"GET /login.php?user=admin&pass=admin' OR '1'='1 HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n"
    pkt1 = IP(src=src_ip, dst=dst_ip) / TCP(sport=54001, dport=80, flags="PA", seq=1000, ack=2000) / Raw(load=payload1)
    pkt1.time = 1700000000.0

    payload2 = b"GET /index.html HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n"
    pkt2 = IP(src=src_ip, dst=dst_ip) / TCP(sport=54002, dport=80, flags="PA", seq=1100, ack=2000) / Raw(load=payload2)
    pkt2.time = 1700000001.0

    wrpcap(str(output_path), [pkt1, pkt2])


if __name__ == "__main__":
    pcap_file = Path("TEST/EXERCISE-3/pcap/case13_multi_match.pcap")
    generate_pcap(pcap_file)

