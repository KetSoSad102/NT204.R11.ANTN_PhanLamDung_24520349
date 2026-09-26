from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, wrpcap


def main() -> None:
    output = Path("TEST/dns_response.pcap")

    packet = (
        IP(
            src="8.8.8.8",
            dst="10.0.0.10",
        )
        / UDP(
            sport=53,
            dport=53000,
        )
        / DNS(
            id=0x1234,
            qr=1,
            aa=1,
            qd=DNSQR(
                qname="example.com",
                qtype="A",
            ),
            an=DNSRR(
                rrname="example.com.",
                type="A",
                ttl=300,
                rdata="93.184.216.34",
            ),
        )
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), [packet])

    print(f"Created {output}")
    print("Packets: 1")


if __name__ == "__main__":
    main()
