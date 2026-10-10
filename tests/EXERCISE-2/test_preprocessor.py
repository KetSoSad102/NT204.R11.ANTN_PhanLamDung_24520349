from __future__ import annotations

from ids_parser.models import NormalizedEvent
from ids_parser.preprocessor import (
    normalize_domain,
    normalize_headers,
    normalize_uri_path,
    preprocess_event,
)


def test_t05_normalize_domain():
    assert normalize_domain("EXAMPLE.COM.") == "example.com"
    assert normalize_domain("Sub.Domain.Net.") == "sub.domain.net"


def test_t05_normalize_uri_path():
    assert normalize_uri_path("//api///v1//login") == "/api/v1/login"
    assert normalize_uri_path("index.html") == "/index.html"


def test_t05_normalize_headers():
    raw_headers = {
        "Host": "Example.com",
        "Content-Type": "text/html",
        "USER-AGENT": "Mozilla/5.0",
    }
    normalized = normalize_headers(raw_headers)
    assert "host" in normalized
    assert "content-type" in normalized
    assert "user-agent" in normalized
    assert normalized["host"] == "Example.com"


def test_t05_normalize_http_event():
    event = NormalizedEvent(
        packet_id=1,
        timestamp=1700000000.123,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        network_protocol="ipv4",
        transport_protocol="tcp",
        src_port=50000,
        dst_port=80,
        application_protocol="http",
        application_data={
            "headers": {"Host": "EXAMPLE.COM", "ACCEPT": "*/*"},
            "target": "//search///items",
            "decoded_uri": "//search///items",
        },
    )

    processed = preprocess_event(event)

    assert processed.network_protocol == "IPv4"
    assert processed.transport_protocol == "TCP"
    assert processed.application_protocol == "HTTP"
    assert processed.application_data["headers"] == {"host": "EXAMPLE.COM", "accept": "*/*"}
    assert processed.application_data["target"] == "/search/items"
    assert processed.application_data["decoded_uri"] == "/search/items"


def test_t05_normalize_dns_event():
    event = NormalizedEvent(
        packet_id=2,
        timestamp=1700000001.0,
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        network_protocol="IPv4",
        transport_protocol="udp",
        src_port=53000,
        dst_port=53,
        application_protocol="dns",
        application_data={
            "domain": "WWW.GOOGLE.COM.",
            "answers": [{"name": "WWW.GOOGLE.COM.", "type": "A"}],
        },
    )

    processed = preprocess_event(event)

    assert processed.transport_protocol == "UDP"
    assert processed.application_protocol == "DNS"
    assert processed.application_data["domain"] == "www.google.com"
    assert processed.application_data["answers"][0]["name"] == "www.google.com"

