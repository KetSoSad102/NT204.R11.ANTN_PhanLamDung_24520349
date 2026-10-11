from pathlib import Path

from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap


def main() -> None:
    output = Path("TEST/EXERCISE-2/pcap/t11_concurrent_flows.pcap")

    packets = [
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=40001, dport=80, flags="PA")
            / b"GET /flowA HTTP/1.1\r\nHost: example.com\r\n\r\n"
        ),
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=40002, dport=80, flags="PA")
            / b"GET /flowB HTTP/1.1\r\nHost: example.com\r\n\r\n"
        ),
        (
            IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=80, dport=40001, flags="PA")
            / b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA"
        ),
        (
            IP(src="10.0.0.1", dst="8.8.8.8")
            / UDP(sport=53000, dport=53)
            / DNS(id=0x5555, rd=1, qd=DNSQR(qname="concurrent.test"))
        ),
        (
            IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=80, dport=40002, flags="PA")
            / b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB"
        ),
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()

