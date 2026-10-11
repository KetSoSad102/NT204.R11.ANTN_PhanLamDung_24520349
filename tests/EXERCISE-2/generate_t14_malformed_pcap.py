from pathlib import Path

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap


def main() -> None:
    output = Path("TEST/EXERCISE-2/pcap/t14_malformed.pcap")

    p1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80, flags="S")
    p1.time = 1700000000.0

    p2 = IP(src="10.0.0.1", dst="10.0.0.2", proto=1) / Raw(load=b"\x08\x00\xf7\xff\x00\x01\x00\x01ping")
    p2.time = 1700000000.1

    p3 = IP(src="10.0.0.1", dst="10.0.0.2") / Raw(load=b"corrupted_tcp_data")
    p3[IP].proto = 6
    p3.time = 1700000000.2

    p4 = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(id=1, rd=1, qd=DNSQR(qname="malformed-test.com"))
    p4.time = 1700000000.3

    packets = [p1, p2, p3, p4]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()

