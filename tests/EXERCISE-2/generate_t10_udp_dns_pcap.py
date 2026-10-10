from pathlib import Path

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, wrpcap


def main() -> None:
    output = Path("TEST/EXERCISE-2/pcap/t10_udp_dns.pcap")

    packets = [
        (
            IP(src="192.168.1.10", dst="8.8.8.8")
            / UDP(sport=53000, dport=53)
            / DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com"))
        ),
        (
            IP(src="8.8.8.8", dst="192.168.1.10")
            / UDP(sport=53, dport=53000)
            / DNS(
                id=0x1234,
                qr=1,
                aa=1,
                qd=DNSQR(qname="example.com"),
                an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34", ttl=300),
            )
        ),
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()

