import http.client
import io
import socket
import threading
import uuid
import tempfile
import hashlib

from warcforhumans.warc.api import WARCRecord, WARCFile

try:
    import urllib3.connection
    has_urllib3 = True
except ImportError:
    has_urllib3 = False

_thread_local = threading.local()
warc_file: WARCFile = None

_original_httpconnection_send = http.client.HTTPConnection.send

def logging_send(self, data: bytes):
    # todo might have to patch socket.send for potential re-encoding into iso-8859-1?
    if not warc_file:
        return _original_httpconnection_send(self, data)

    warc_file.flush_pending()
    _cleanup_records()
    print(f"[HTTPConnection.send] {len(data)}:\n{data!r}\n")

    # Neither the HTTPConnection nor HTTPResponse store the full URL,
    # so here we have to manually reconstruct it
    url = str()
    protocol = None
    print(self.__class__)
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

    url += protocol
    url += "://"
    url += self.host

    if protocol == "http" and self.port != 80 and self.port is not None:
        url += f":{self.port}"
    elif protocol == "https" and self.port != 443 and self.port is not None:
        url += f":{self.port}"

    try:
        first_line = data.split(b"\r\n", 1)[0]
        parts = first_line.split(b" ")
        if len(parts) >= 2:
            path = parts[1].decode("utf-8", errors="replace")
            url += path
        else:
            raise ValueError("Couldn't parse request line")
    except Exception:
        raise

    _thread_local.request_url = url

    if self.sock is None:
        if not self.auto_open:
            raise http.client.NotConnected()
        self.connect()

    warc_record = WARCRecord("request", "application/http;msgtype=request")
    warc_record.set_header("WARC-Target-URI", url)
    warc_record.set_header("WARC-Block-Digest", "sha1:" + hashlib.sha1(data).hexdigest())
    warc_record.add_header("WARC-Protocol", self._http_vsn_str.lower())
    warc_record.add_headers_for_socket(self.sock)
    warc_record.set_content(data)

    _thread_local.request_warc_record = warc_record
    print(f"[HTTPConnection.send] Request ID: {_thread_local.request_warc_record.get_id()}, URL: {url}")

    warc_content = str()
    for chunk in warc_record.serialize_stream():
        warc_content += chunk.decode("utf-8", errors="replace")
    print(f"[WARC Request Record]\n{warc_content}\n")


    return _original_httpconnection_send(self, data)

http.client.HTTPConnection.send = logging_send

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
    if not warc_file:
        return _original_httpresponse_init(self, sock, debuglevel=debuglevel, method=method, url=url)

    if not hasattr(_thread_local, 'request_warc_record'):
        raise ValueError("No request record found in thread-local storage")

    print(
        f"[HTTPResponseWrapper] Intercepting response for request ID: {_thread_local.request_warc_record.get_id()}")
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
            payload_hash.update(chunk_size_line)
            temp_file.write(chunk_size_line)
            try:
                chunk_size = int(chunk_size_line.split(b";", 1)[0].strip(), 16)
            except ValueError:
                break
            if chunk_size == 0:
                trailing = fp.read(2) # Read the trailing \r\n
                temp_file.write(trailing)
                block_hash.update(trailing)
                payload_hash.update(trailing)
                break
            to_read = chunk_size + 2  # include trailing \r\n
            while to_read > 0:
                chunk = fp.read(min(2048, to_read))
                temp_file.write(chunk)
                block_hash.update(chunk)
                payload_hash.update(chunk)
                to_read -= len(chunk)

    temp_file.seek(0)  # Reset file pointer for reading
    print(f"[HTTPResponseWrapper] Response written to temporary file")
    print(f"[HTTPResponseWrapper] Full response preview:\n{temp_file.read()!r}\n")
    warc_record = WARCRecord("response", "application/http;msgtype=response")
    warc_record.set_header("WARC-Target-URI", _thread_local.request_url)
    warc_record.set_header("WARC-Concurrent-To", _thread_local.request_warc_record.get_id())
    warc_record.set_header("WARC-Block-Digest", "sha1:" + block_hash.hexdigest())
    warc_record.set_header("WARC-Payload-Digest", "sha1:" + payload_hash.hexdigest())
    warc_record.add_header("WARC-Protocol", http_version)
    warc_record.add_headers_for_socket(sock)
    warc_record.set_content_stream(temp_file) # The warc record will close the temp file when the record gets closed

    _thread_local.response_warc_record = warc_record

    temp_file.seek(0)
    _original_httpresponse_init(self, sock=FakeSocket(temp_file.read()), debuglevel=debuglevel, method=method, url=url)

    warc_file.next_request_pair(_thread_local.request_warc_record, _thread_local.response_warc_record)
    _cleanup_records()

http.client.HTTPResponse.__init__ = httpresponse_init


_original_httpconnection_putrequest = http.client.HTTPConnection.putrequest

def logging_putrequest(self, method, url, *args, **kwargs):
    print(f"[HTTPConnection.putrequest] Method: {method}, URL: {url}")
    return _original_httpconnection_putrequest(self, method, url, *args, **kwargs)


# Patch
http.client.HTTPConnection.putrequest = logging_putrequest



def _cleanup_records():
    if hasattr(_thread_local, 'response_warc_record'):
        del _thread_local.response_warc_record
    if hasattr(_thread_local, 'request_warc_record'):
        del _thread_local.request_warc_record
    if hasattr(_thread_local, 'request_url'):
        del _thread_local.request_url