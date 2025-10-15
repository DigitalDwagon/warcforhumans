import base64
import hashlib
import http.client
import io
import tempfile
import threading

from warcforhumans.api import WARCRecord, WARCWriter

try:
    import urllib3.connection
    has_urllib3 = True
except ImportError:
    has_urllib3 = False

_thread_local = threading.local()
warc_writer: WARCWriter | None = None

_original_httpconnection_send = http.client.HTTPConnection.send

def wrapped_send(self, data):
    if not warc_writer:
        return _original_httpconnection_send(self, data)

    warc_writer.flush_pending()

    if not hasattr(_thread_local, 'request_temp_file'):
        _thread_local.request_temp_file = tempfile.TemporaryFile()

    if self._is_textIO(data):
        # HTTPConnection.send will re-encode this before sending it on.
        # To get proper bytes into the WARC, we have to encode it to bytes here,
        # which will make http.client send it verbatim.
        encoded_data = b""
        while chunk := data.read(2048):
            encoded_data += chunk.encode("iso-8859-1")
        data = encoded_data

    _thread_local.request_temp_file.write(data)
    return _original_httpconnection_send(self, data)

http.client.HTTPConnection.send = wrapped_send

_original_httpconnection_getresponse = http.client.HTTPConnection.getresponse

def wrapped_getresponse(self, *args, **kwargs):
    if not warc_writer:
        return _original_httpconnection_getresponse(self, *args, **kwargs)
    if not hasattr(_thread_local, 'request_temp_file'):
        raise ValueError("No request data found in thread-local storage")

    temp_file = _thread_local.request_temp_file

    # Neither the HTTPConnection nor HTTPResponse store the full URL,
    # so here we have to manually reconstruct it
    if type(self) == http.client.HTTPSConnection:
        protocol = "https"
    elif type(self) == http.client.HTTPConnection:
        protocol = "http"
    elif has_urllib3 and type(self) == urllib3.connection.HTTPSConnection:
        protocol = "https"
    elif has_urllib3 and type(self) == urllib3.connection.HTTPConnection:
        protocol = "http"
    # TODO: It might be better here to just match for names "HTTPConnection" and "HTTPSConnection"?
    # But I wanted to play it safe for now.
    else:
        raise TypeError("Unknown connection type")

    url = protocol
    url += "://"
    url += self.host

    if protocol == "http" and self.port != 80 and self.port is not None:
        url += f":{self.port}"
    elif protocol == "https" and self.port != 443 and self.port is not None:
        url += f":{self.port}"

    try:
        temp_file.seek(0)
        first_line = temp_file.readline(65537)
        parts = first_line.split(b" ")
        if len(parts) >= 2:
            path = parts[1].decode("utf-8")
            url += path
            # TODO this could probably be more robust
        else:
            raise ValueError("Couldn't parse request line")
    except Exception:
        raise

    _thread_local.request_url = url

    # We have to ensure the connection is open here to get the IP address for the WARC headers.
    if self.sock is None:
        raise ValueError("Connection socket is not open")

    block_digest = hashlib.sha1()
    temp_file.seek(0)
    while chunk := temp_file.read(2048):
        block_digest.update(chunk)

    warc_record = WARCRecord("request", "application/http;msgtype=request")
    warc_record.set_header("WARC-Target-URI", url)
    warc_record.set_header("WARC-Block-Digest", get_hash_string(block_digest))
    warc_record.add_header("WARC-Protocol", self._http_vsn_str.lower())
    warc_record.add_headers_for_socket(self.sock)
    temp_file.seek(0)
    warc_record.set_content_stream(temp_file, close=True)
    _thread_local.request_warc_record = warc_record

    return _original_httpconnection_getresponse(self, *args, **kwargs)

http.client.HTTPConnection.getresponse = wrapped_getresponse

class FakeSocket:
    def __init__(self, data: bytes):
        self._file = io.BytesIO(data)

    def makefile(self, *args, **kwargs):
        return self._file

    def recv(self, amt: int = 4096) -> bytes:
        return self._file.read(amt)

    def close(self):
        pass

_original_httpresponse_init = http.client.HTTPResponse.__init__


def httpresponse_init(self, sock, debuglevel=0, method=None, url=None):
    # http.client natively provides no way to intercept the raw response bytes.
    # Unfortunately, this means we have to re-implement a lot of logic in order to
    # read in the full response ourselves.
    # We then write those bytes to a temporary file, and pass it to the original
    # __init__ method with a fake socket object.
    if not warc_writer:
        return _original_httpresponse_init(self, sock, debuglevel=debuglevel, method=method, url=url)

    if not hasattr(_thread_local, 'request_warc_record'):
        raise ValueError("No request record found in thread-local storage")

    fp = sock.makefile("rb", buffering=0)
    temp_file = tempfile.TemporaryFile()

    block_hash = hashlib.sha1()

    # Read up through the end of the header block.
    while True:
        line = fp.readline(65537)
        block_hash.update(line)
        temp_file.write(line)
        if not line or line == b"\r\n":
            break

    temp_file.seek(0)
    content_length = None
    transfer_encoding = None

    # Have to grab the HTTP version from the status line for WARC headers
    http_version = temp_file.readline(65537).decode("utf-8").split(" ", 1)[0].lower()

    for header in temp_file:
        # TODO: this header parsing could probably be more robust
        if header.lower().startswith(b"content-length:"):
            try:
                content_length = int(header.split(b":", 1)[1].strip())
            except ValueError:
                pass
        elif header.lower().startswith(b"transfer-encoding:"):
            transfer_encoding = header.split(b":", 1)[1].strip().lower()

    temp_file.seek(0, io.SEEK_END)
    payload_hash = hashlib.sha1()

    # TODO: What if the connection times out or is closed early?
    if content_length is not None:
        to_read = content_length
        while to_read > 0:
            chunk = fp.read(min(2048, to_read))
            temp_file.write(chunk)
            block_hash.update(chunk)
            payload_hash.update(chunk)
            to_read -= len(chunk)

    elif transfer_encoding == b"chunked":
        while True:
            chunk_size_line = fp.readline()
            block_hash.update(chunk_size_line)
            temp_file.write(chunk_size_line)
            try:
                chunk_size = int(chunk_size_line.split(b";", 1)[0].strip(), 16)
            except ValueError:
                break
            to_read = chunk_size
            while to_read > 0:
                chunk = fp.read(min(2048, to_read))
                temp_file.write(chunk)
                block_hash.update(chunk)
                # The payload hash is defined as the hash of the "entity-body" and therefore doesn't include chunk headers or footers, per RFC 2616 section 3.6
                payload_hash.update(chunk)
                to_read -= len(chunk)

            trailing = fp.read(2) # Read the trailing \r\n
            temp_file.write(trailing)
            block_hash.update(trailing)

            if chunk_size == 0 and trailing != b"\r\n":
                while True:
                    line = fp.readline(65537)
                    block_hash.update(line)
                    temp_file.write(line)
                    if not line or line == b"\r\n":
                        break
            if chunk_size == 0:
                break




    temp_file.seek(0)

    warc_record = WARCRecord("response", "application/http;msgtype=response")
    warc_record.set_header("WARC-Target-URI", _thread_local.request_url)
    warc_record.set_header("WARC-Concurrent-To", _thread_local.request_warc_record.get_id())
    warc_record.set_header("WARC-Block-Digest", get_hash_string(block_hash))
    warc_record.set_header("WARC-Payload-Digest", get_hash_string(payload_hash))
    warc_record.add_header("WARC-Protocol", http_version)
    warc_record.add_headers_for_socket(sock)

    close_file = False
    revisit, headers = warc_writer.check_for_revisit(get_hash_string(payload_hash))
    if revisit:
        warc_record.set_type("revisit")
        warc_record.add_headers(headers)
        content = b""
        # revisit content is up to the end of the header block
        while True:
            line = temp_file.readline(65537)
            content += line
            if not line or line == b"\r\n":
                break
        warc_record.set_content(content)
        close_file = True
    else:
        warc_record.set_content_stream(temp_file, close=True) # The warc record will close the temp file when the record gets closed

    warc_writer.pending_records.extend([_thread_local.request_warc_record, warc_record])
    _cleanup_records()

    temp_file.seek(0) # to let http.client parse the whole response itself
    _original_httpresponse_init(self, sock=FakeSocket(temp_file.read()), debuglevel=debuglevel, method=method, url=url)
    if close_file:
        temp_file.close()

http.client.HTTPResponse.__init__ = httpresponse_init

"""
_original_httpconnection_putrequest = http.client.HTTPConnection.putrequest

def logging_putrequest(self, method, url, *args, **kwargs):
    print(f"[HTTPConnection.putrequest] Method: {method}, URL: {url}")
    return _original_httpconnection_putrequest(self, method, url, *args, **kwargs)


http.client.HTTPConnection.putrequest = logging_putrequest
"""


def _cleanup_records():
    if hasattr(_thread_local, 'response_warc_record'):
        del _thread_local.response_warc_record
    if hasattr(_thread_local, 'request_warc_record'):
        del _thread_local.request_warc_record
    if hasattr(_thread_local, 'request_url'):
        del _thread_local.request_url
    if hasattr(_thread_local, 'request_temp_file'):
        del _thread_local.request_temp_file

def get_hash_string(hash) -> str:
    return "sha1:" + base64.b32encode(hash.digest()).decode("utf-8")