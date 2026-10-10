from pathlib import Path

from scapy.all import IP, TCP, wrpcap


def main() -> None:
    output = Path("TEST/EXERCISE-2/pcap/t08_bidirectional_flow.pcap")

    packets = [
        (
            IP(src="192.168.1.10", dst="192.168.1.20")
            / TCP(sport=45000, dport=80, flags="PA")
            / b"GET /data HTTP/1.1\r\nHost: example.com\r\n\r\n"
        ),
        (
            IP(src="192.168.1.20", dst="192.168.1.10")
            / TCP(sport=80, dport=45000, flags="PA")
            / b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
        ),
        (
            IP(src="192.168.1.10", dst="192.168.1.20")
            / TCP(sport=45000, dport=80, flags="A")
        ),
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()

