from pathlib import Path

from scapy.all import DNS, DNSQR, IP, UDP, wrpcap


def main() -> None:
    output = Path("TEST/pcap/dns_query.pcap")

    packet = (
        IP(
            src="10.0.0.10",
            dst="8.8.8.8",
        )
        / UDP(
            sport=53000,
            dport=53,
        )
        / DNS(
            id=0x1234,
            qr=0,
            rd=1,
            qd=DNSQR(
                qname="example.com",
                qtype="A",
            ),
        )
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), [packet])

    print(f"Created {output}")
    print("Packets: 1")


if __name__ == "__main__":
    main()
