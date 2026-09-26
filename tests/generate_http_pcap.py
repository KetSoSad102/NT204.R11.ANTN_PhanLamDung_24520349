from pathlib import Path

from scapy.all import IP, TCP, wrpcap


def main() -> None:
    output = Path("TEST/pcap/http_requests.pcap")

    packets = [
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, flags="PA")
            / (
                b"GET /index.html HTTP/1.1\r\n"
                b"Host: example.com\r\n"
                b"User-Agent: test-client\r\n"
                b"\r\n"
            )
        ),
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12346, dport=80, flags="PA")
            / (
                b"POST /login HTTP/1.1\r\n"
                b"Host: example.com\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n"
                b"Content-Length: 27\r\n"
                b"\r\n"
                b"username=admin&password=123"
            )
        ),
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()
