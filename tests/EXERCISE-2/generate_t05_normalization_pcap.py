from pathlib import Path

from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap


def main() -> None:
    output = Path("TEST/EXERCISE-2/pcap/t05_normalization.pcap")

    packets = [
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, flags="PA")
            / (
                b"GET //api///items//view HTTP/1.1\r\n"
                b"HOST: Example.COM\r\n"
                b"USER-AGENT: TestClient\r\n"
                b"ACCEPT: */*\r\n"
                b"\r\n"
            )
        ),
        (
            IP(src="10.0.0.1", dst="8.8.8.8")
            / UDP(sport=53000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="EXAMPLE.COM."))
        ),
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()

