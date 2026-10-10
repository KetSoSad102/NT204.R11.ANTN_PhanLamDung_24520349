from pathlib import Path

from scapy.all import IP, TCP, wrpcap


def main() -> None:
    output = Path("TEST/EXERCISE-2/pcap/t09_tcp_close.pcap")

    packets = [
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51000, dport=80, flags="S", seq=100)
        ),
        (
            IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=80, dport=51000, flags="SA", seq=200, ack=101)
        ),
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51000, dport=80, flags="A", seq=101, ack=201)
        ),
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51000, dport=80, flags="FA", seq=101, ack=201)
        ),
        (
            IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=80, dport=51000, flags="A", seq=201, ack=102)
        ),
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=52000, dport=80, flags="S", seq=300)
        ),
        (
            IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=80, dport=52000, flags="R", seq=0, ack=301)
        ),
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()

