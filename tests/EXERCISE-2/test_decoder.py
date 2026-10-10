from __future__ import annotations

from ids_parser.decoder import decode_event, decode_url
from ids_parser.models import NormalizedEvent


def test_t01_http_url_decode_direct():

    raw_encoded = "/search?query=%27%20OR%201%3D1"
    decoded = decode_url(raw_encoded)
    assert decoded == "/search?query=' OR 1=1"


def test_t01_http_url_decode_event():

    raw_uri = "/login?user=admin%27%20OR%201%3D1&pass=123%23"
    event = NormalizedEvent(
        packet_id=1,
        timestamp=1700000000.0,
        src_ip="192.168.1.100",
        dst_ip="192.168.1.1",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=50000,
        dst_port=80,
        application_protocol="HTTP",
        application_data={
            "message_type": "request",
            "method": "GET",
            "target": raw_uri,
            "version": "HTTP/1.1",
            "headers": {"Host": "example.com"},
            "body": "",
        },
    )

    processed_event = decode_event(event)

    app_data = processed_event.application_data

    assert app_data["raw_uri"] == raw_uri
    assert app_data["target"] == raw_uri


    expected_decoded = "/login?user=admin' OR 1=1&pass=123#"
    assert app_data["decoded_uri"] == expected_decoded

