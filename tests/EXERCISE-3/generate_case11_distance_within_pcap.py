from __future__ import annotations

from pathlib import Path
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap


def generate_pcap(output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    src_ip = "192.168.1.100"
    dst_ip = "10.0.0.1"

    payload1 = b"USER admin KEY=12345 AUTH TOKEN= 123 SUCCESS"
    pkt1 = IP(src=src_ip, dst=dst_ip) / TCP(sport=52001, dport=80, flags="PA", seq=1000, ack=2000) / Raw(load=payload1)
    pkt1.time = 1700000000.0

    payload2 = b"USER is not a regular user, far away is admin"
    pkt2 = IP(src=src_ip, dst=dst_ip) / TCP(sport=52002, dport=80, flags="PA", seq=1100, ack=2000) / Raw(load=payload2)
    pkt2.time = 1700000001.0

    wrpcap(str(output_path), [pkt1, pkt2])


if __name__ == "__main__":
    pcap_file = Path("TEST/EXERCISE-3/pcap/case11_distance_within.pcap")
    generate_pcap(pcap_file)

