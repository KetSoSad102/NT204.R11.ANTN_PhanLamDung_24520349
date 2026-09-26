from pathlib import Path

from scapy.all import IP, TCP, wrpcap


def main() -> None:
    output = Path("TEST/pcap/smtp_response.pcap")

    packets = [
        (
            IP(src="10.0.0.20", dst="10.0.0.10")
            / TCP(sport=25, dport=51000, flags="PA")
            / b"220 mail.example.com ESMTP\r\n"
        ),
        (
            IP(src="10.0.0.20", dst="10.0.0.10")
            / TCP(sport=25, dport=51000, flags="PA")
            / b"250 mail.example.com OK\r\n"
        ),
        (
            IP(src="10.0.0.20", dst="10.0.0.10")
            / TCP(sport=25, dport=51000, flags="PA")
            / b"221 mail.example.com closing connection\r\n"
        ),
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()
