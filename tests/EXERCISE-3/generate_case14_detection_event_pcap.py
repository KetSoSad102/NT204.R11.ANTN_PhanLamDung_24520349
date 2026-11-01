from __future__ import annotations

from pathlib import Path
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap


def generate_pcap(output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    http_payload = b"GET /../../etc/passwd HTTP/1.1\r\nHost: 192.168.1.20\r\n\r\n"
    pkt1 = IP(src="10.0.0.5", dst="192.168.1.20") / TCP(sport=52133, dport=80, flags="PA", seq=1000, ack=2000) / Raw(load=http_payload)
    pkt1.time = 1700000000.0

    dns_payload = DNS(rd=1, qd=DNSQR(qname="evil.com"))
    pkt2 = IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=45678, dport=53) / dns_payload
    pkt2.time = 1700000001.0

    wrpcap(str(output_path), [pkt1, pkt2])


if __name__ == "__main__":
    pcap_file = Path("TEST/EXERCISE-3/pcap/case14_detection_event.pcap")
    generate_pcap(pcap_file)

