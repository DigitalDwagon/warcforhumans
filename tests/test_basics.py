import pytest

def test_simple_warc(verify_content_match):
    print(verify_content_match(b"HTTP/1.1 200 OK\r\n\r\nHello, world!\r\n\r\n"))