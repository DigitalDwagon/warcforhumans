"""
Tests to verify that bytes after the HTTP message boundary are not recorded in the WARC file.

Bytes sent after the end of the HTTP message (eg. additional content sent after Content-Length or after the end of a
chunked encoding message) are not part of the HTTP response and should not be recorded in the WARC file.
"""
import pytest


@pytest.fixture
def verify_no_extra_bytes(tmp_path, warc_writer, fake_http_server):
    """
    Helper fixture that verifies extra bytes after HTTP message boundary are excluded.
    
    Takes response_without_extra and response_with_extra, ensures the WARC file contains
    the valid response but NOT the extra bytes.
    """
    def verify(response_without_extra, response_with_extra):
        session = warc_writer.get_session()
        session.get(fake_http_server(response_with_extra))
        warc_writer.close()
        
        fp = tmp_path / "test.warc"
        assert fp.exists(), "WARC file does not exist"
        
        with open(fp, "rb") as f:
            file_content = f.read()
            assert response_without_extra in file_content, "Valid response not found in WARC file!"
            
            # Extract the "extra bytes" marker (everything after the valid response)
            extra_bytes = response_with_extra[len(response_without_extra):]
            assert extra_bytes not in file_content, f"Extra bytes were recorded in WARC file: {extra_bytes!r}"
    
    return verify


class TestContentLengthBoundary:
    """Tests for Content-Length based message boundaries"""
    
    def test_content_length_single_chunk_no_extra_bytes(self, verify_content_match):
        """Content-Length response that fits in single chunk with no extra bytes"""
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!"
        verify_content_match(response)

    def test_content_length_single_chunk_with_extra_bytes(self, verify_no_extra_bytes):
        """Content-Length response with extra bytes appended (should be excluded)"""
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!"
        response_with_extra = response + b"\r\n\r\nEXTRA JUNK DATA"
        verify_no_extra_bytes(response, response_with_extra)

    def test_content_length_multiple_chunks_with_extra_bytes(self, verify_content_match):
        """Content-Length response spread across chunks with extra bytes"""
        body = b"Hello, world! Extra texts"  # Exactly 25 bytes
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 25\r\n\r\n" + body
        verify_content_match(response)

    def test_content_length_zero(self, verify_content_match):
        """Content-Length: 0 response (no body)"""
        response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
        verify_content_match(response)

    def test_content_length_zero_with_extra_bytes(self, verify_no_extra_bytes):
        """Content-Length: 0 with extra bytes appended"""
        response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
        response_with_extra = response + b"GARBAGE DATA"
        verify_no_extra_bytes(response, response_with_extra)


class TestChunkedTransferEncoding:
    """Tests for chunked transfer encoding message boundaries"""
    
    def test_chunked_single_chunk_response_no_extra(self, verify_content_match):
        """Chunked transfer encoding with single chunk, no extra bytes"""
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"d\r\n"  # 13 bytes in hex
            b"Hello, world!\r\n"
            b"0\r\n"  # end chunk
            b"\r\n"   # trailing CRLF
        )
        verify_content_match(response)

    def test_chunked_single_chunk_response_with_extra_bytes(self, verify_no_extra_bytes):
        """Chunked response with extra bytes after the end chunk"""
        response_without_extra = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"d\r\n"  # 13 bytes in hex
            b"Hello, world!\r\n"
            b"0\r\n"  # end chunk
            b"\r\n"   # trailing CRLF
        )
        response_with_extra = response_without_extra + b"JUNK DATA AFTER ENCODING"
        verify_no_extra_bytes(response_without_extra, response_with_extra)

    def test_chunked_multiple_chunks_response(self, verify_content_match):
        """Chunked transfer encoding with multiple chunks"""
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"5\r\n"      # 5 bytes
            b"Hello\r\n"
            b"7\r\n"      # 7 bytes
            b", world\r\n"
            b"0\r\n"      # end chunk
            b"\r\n"
        )
        verify_content_match(response)

    def test_chunked_with_chunk_extensions_and_trailers(self, verify_content_match):
        """Chunked encoding with chunk extensions and trailers (trailer headers after end chunk)"""
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Trailer: X-Checksum\r\n"
            b"\r\n"
            b"d\r\n"  # 13 bytes
            b"Hello, world!\r\n"
            b"0\r\n"  # end chunk
            b"X-Checksum: abc123\r\n"  # trailer header
            b"\r\n"
        )
        verify_content_match(response)

    def test_chunked_with_extra_bytes_after_trailers(self, verify_no_extra_bytes):
        """Chunked with trailers and extra bytes after"""
        response_without_extra = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Trailer: X-Checksum\r\n"
            b"\r\n"
            b"d\r\n"  # 13 bytes
            b"Hello, world!\r\n"
            b"0\r\n"  # end chunk
            b"X-Checksum: abc123\r\n"  # trailer header
            b"\r\n"
        )
        response_with_extra = response_without_extra + b"EXTRA GARBAGE"
        verify_no_extra_bytes(response_without_extra, response_with_extra)


class TestLargeResponses:
    """Tests with larger response bodies"""
    
    def test_large_content_length_response(self, verify_content_match):
        """Large response with Content-Length"""
        body = b"X" * 10000
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" +
            body
        )
        verify_content_match(response)

    def test_large_content_length_with_extra_bytes(self, verify_no_extra_bytes):
        """Large Content-Length response with extra bytes"""
        body = b"X" * 10000
        response_without_extra = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" +
            body
        )
        response_with_extra = response_without_extra + b"\r\n\r\nPIPELINED REQUEST OR GARBAGE"
        verify_no_extra_bytes(response_without_extra, response_with_extra)

    def test_large_chunked_response(self, verify_content_match):
        """Large chunked response with multiple chunks"""
        chunks = []
        for i in range(100):
            chunk_data = f"Chunk {i}: " + "X" * 90 + "\n"
            chunk_bytes = chunk_data.encode()
            chunk_size_hex = f"{len(chunk_bytes):x}".encode()
            chunks.append(chunk_size_hex + b"\r\n" + chunk_bytes + b"\r\n")
        
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n" +
            b"".join(chunks) +
            b"0\r\n"
            b"\r\n"
        )
        verify_content_match(response)


class TestEdgeCases:
    """Edge case tests"""
    
    def test_response_with_crlf_in_body_and_extra_bytes(self, verify_no_extra_bytes):
        """Response body contains CRLF sequences but extra bytes come after Content-Length"""
        body = b"Line 1\r\nLine 2\r\nLine 3"
        response_without_extra = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" +
            body
        )
        response_with_extra = response_without_extra + b"\r\n\r\nGARBAGE"
        verify_no_extra_bytes(response_without_extra, response_with_extra)

    def test_binary_content_with_extra_bytes(self, verify_content_match):
        """Binary content (all byte values) with proper Content-Length"""
        body = bytes(range(256)) * 4  # All possible byte values repeated
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" +
            body
        )
        verify_content_match(response)






