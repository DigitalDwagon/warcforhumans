import pytest
from h11._util import RemoteProtocolError

def test_simple_warc(verify_content_match):
    verify_content_match(b"HTTP/1.1 200 OK\r\n\r\nHello, world!\r\n\r\n")

def test_non_chunked_encoding(verify_content_match):
    verify_content_match(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello\r\n\r\n")

