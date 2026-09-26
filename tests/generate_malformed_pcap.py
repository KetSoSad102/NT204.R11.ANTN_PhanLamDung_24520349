from pathlib import Path

from scapy.all import Ether, Raw, wrpcap


def main() -> None:
    output = Path("TEST/malformed.pcap")

    packets = [
        Ether(
            src="02:00:00:00:00:01",
            dst="02:00:00:00:00:02",
            type=0x88B5,
        ) / Raw(load=b"\x00\xff\x01\x02\x03\x04"),

        Ether(
            src="02:00:00:00:00:03",
            dst="02:00:00:00:00:04",
            type=0x88B5,
        ) / Raw(load=b"this is not an IPv4 packet"),
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()