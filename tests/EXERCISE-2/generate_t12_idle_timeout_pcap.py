from pathlib import Path

from scapy.all import IP, UDP, DNS, DNSQR, wrpcap


def main() -> None:
    output = Path("TEST/EXERCISE-2/pcap/t12_idle_timeout.pcap")

    p1 = (
        IP(src="10.0.0.1", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(id=1, rd=1, qd=DNSQR(qname="before-timeout.test"))
    )
    p1.time = 1700000000.0

    p2 = (
        IP(src="10.0.0.1", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(id=2, rd=1, qd=DNSQR(qname="after-timeout.test"))
    )
    p2.time = 1700000100.0

    packets = [p1, p2]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()

