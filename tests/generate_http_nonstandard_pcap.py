from pathlib import Path

from scapy.all import IP, TCP, wrpcap


def main() -> None:
    output = Path("TEST/pcap/http_nonstandard_port.pcap")

    packet = (
        IP(
            src="10.0.0.10",
            dst="10.0.0.20",
        )
        / TCP(
            sport=45000,
            dport=8088,
            flags="PA",
        )
        / (
            b"GET /admin HTTP/1.1\r\n"
            b"Host: example.com:8088\r\n"
            b"User-Agent: ids-test\r\n"
            b"\r\n"
        )
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), [packet])

    print(f"Created {output}")
    print("Packets: 1")
    print("Destination port: 8088")


if __name__ == "__main__":
    main()
