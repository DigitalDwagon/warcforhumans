import pytest

def test_simple_warc(verify_content_match):
    print(verify_content_match(b"HTTP/1.1 200 OK\r\n\r\nHello, world!\r\n\r\n"))

def test_non_chunked_encoding(verify_content_match):
    with pytest.raises(NotImplementedError):
        verify_content_match(b"HTTP/1/1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nHello\r\n\r\n")