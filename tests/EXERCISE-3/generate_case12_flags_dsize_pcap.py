from __future__ import annotations

from pathlib import Path
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap


def generate_pcap(output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    src_ip = "192.168.1.100"
    dst_ip = "10.0.0.1"

    pkt1 = IP(src=src_ip, dst=dst_ip) / TCP(sport=53001, dport=80, flags="S", seq=1000)
    pkt1.time = 1700000000.0

    payload2 = b"X" * 70
    pkt2 = IP(src=src_ip, dst=dst_ip) / TCP(sport=53002, dport=80, flags="PA", seq=1100, ack=2000) / Raw(load=payload2)
    pkt2.time = 1700000001.0

    payload3 = b"Y" * 30
    pkt3 = IP(src=src_ip, dst=dst_ip) / TCP(sport=53003, dport=80, flags="PA", seq=1200, ack=2000) / Raw(load=payload3)
    pkt3.time = 1700000002.0

    wrpcap(str(output_path), [pkt1, pkt2, pkt3])


if __name__ == "__main__":
    pcap_file = Path("TEST/BT3/pcap/case12_flags_dsize.pcap")
    generate_pcap(pcap_file)

