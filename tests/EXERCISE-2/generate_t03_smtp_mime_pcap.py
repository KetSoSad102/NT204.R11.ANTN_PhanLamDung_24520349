from pathlib import Path

from scapy.all import IP, TCP, wrpcap


def main() -> None:
    output = Path("TEST/EXERCISE-2/pcap/t03_smtp_mime.pcap")

    packets = [
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=25, flags="PA")
            / (
                b"Content-Type: text/plain; charset=utf-8\r\n"
                b"Content-Transfer-Encoding: base64\r\n"
                b"\r\n"
                b"SGVsbG8gZnJvbSBJRFMh"
            )
        ),
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12346, dport=25, flags="PA")
            / (
                b"Content-Type: text/plain; charset=utf-8\r\n"
                b"Content-Transfer-Encoding: quoted-printable\r\n"
                b"\r\n"
                b"Alert:=20Intrusion=20Detected=3DTrue"
            )
        ),
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()

