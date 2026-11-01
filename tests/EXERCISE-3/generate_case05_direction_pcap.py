from pathlib import Path

from scapy.all import IP, TCP, Raw, wrpcap


def main() -> None:
    output = Path("TEST/BT3/pcap/case05_direction.pcap")

    p1 = (
        IP(src="192.168.1.100", dst="10.0.0.1")
        / TCP(sport=50000, dport=80, flags="PA", seq=1000, ack=2000)
        / Raw(b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n")
    )
    p1.time = 1700000000.0

    p2 = (
        IP(src="10.0.0.1", dst="192.168.1.100")
        / TCP(sport=80, dport=50000, flags="PA", seq=2000, ack=1030)
        / Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    )
    p2.time = 1700000000.1

    packets = [p1, p2]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()

