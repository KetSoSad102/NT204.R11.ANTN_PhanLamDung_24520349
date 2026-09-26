from pathlib import Path

from scapy.all import IP, TCP, wrpcap


def main() -> None:
    output = Path("TEST/pcap/http_response.pcap")

    packet = (
        IP(
            src="10.0.0.2",
            dst="10.0.0.1",
        )
        / TCP(
            sport=80,
            dport=12345,
            flags="PA",
        )
        / (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 5\r\n"
            b"Server: test-server\r\n"
            b"\r\n"
            b"Hello"
        )
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), [packet])

    print(f"Created {output}")
    print("Packets: 1")


if __name__ == "__main__":
    main()
