from pathlib import Path

from scapy.all import IP, TCP, wrpcap


def main() -> None:
    output = Path("TEST/pcap/smtp_command.pcap")

    packets = [
        (
            IP(src="10.0.0.10", dst="10.0.0.20")
            / TCP(sport=51000, dport=25, flags="PA")
            / b"EHLO mail.example.com\r\n"
        ),
        (
            IP(src="10.0.0.10", dst="10.0.0.20")
            / TCP(sport=51000, dport=25, flags="PA")
            / b"MAIL FROM:<alice@example.com>\r\n"
        ),
        (
            IP(src="10.0.0.10", dst="10.0.0.20")
            / TCP(sport=51000, dport=25, flags="PA")
            / b"RCPT TO:<bob@example.com>\r\n"
        ),
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()
