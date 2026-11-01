from __future__ import annotations

from pathlib import Path
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap


def generate_pcap(output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    client_ip = "192.168.1.50"
    server_ip = "10.0.0.1"
    client_port = 49152
    server_port = 80

    pkt1 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="S", seq=1000)
    pkt1.time = 1700000000.0

    pkt2 = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="SA", seq=2000, ack=1001)
    pkt2.time = 1700000000.01

    pkt3 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="A", seq=1001, ack=2001)
    pkt3.time = 1700000000.02

    req_payload = b"GET /index.php?input=EXPLOIT HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n"
    pkt4 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="PA", seq=1001, ack=2001) / Raw(load=req_payload)
    pkt4.time = 1700000000.03

    resp_payload = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nRESPONSE_DATA"
    pkt5 = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="PA", seq=2001, ack=1001 + len(req_payload)) / Raw(load=resp_payload)
    pkt5.time = 1700000000.04

    wrpcap(str(output_path), [pkt1, pkt2, pkt3, pkt4, pkt5])


if __name__ == "__main__":
    pcap_file = Path("TEST/EXERCISE-3/pcap/case08_flow.pcap")
    generate_pcap(pcap_file)

