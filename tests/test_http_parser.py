from ids_parser.http_parser import parse_http


def test_http_get() -> None:
    payload = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: test-client\r\n"
        b"Accept: */*\r\n"
        b"\r\n"
    )

    result = parse_http(payload)

    assert result["message_type"] == "request"
    assert result["method"] == "GET"
    assert result["target"] == "/index.html"
    assert result["version"] == "HTTP/1.1"

    assert result["headers"]["Host"] == "example.com"
    assert result["headers"]["User-Agent"] == "test-client"
    assert result["headers"]["Accept"] == "*/*"

    assert result["body"] == ""

def test_http_post() -> None:
    payload = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 27\r\n"
        b"\r\n"
        b"username=admin&password=123"
    )

    result = parse_http(payload)

    assert result["message_type"] == "request"
    assert result["method"] == "POST"
    assert result["target"] == "/login"
    assert result["version"] == "HTTP/1.1"

    assert result["headers"]["Host"] == "example.com"
    assert (
        result["headers"]["Content-Type"]
        == "application/x-www-form-urlencoded"
    )
    assert result["headers"]["Content-Length"] == "27"

    assert result["body"] == "username=admin&password=123"