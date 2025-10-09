import http.client
import io
import socket
import threading
import uuid
import tempfile

try:
    import urllib3.connection
    has_urllib3 = True
except ImportError:
    has_urllib3 = False

_thread_local = threading.local()

_original_httpconnection_send = http.client.HTTPConnection.send

def logging_send(self, data: bytes):
    # todo might have to patch socket.send for potential re-encoding into iso-8859-1?
    print(f"[HTTPConnection.send] {len(data)}:\n{data!r}\n")
    _thread_local.request_id = uuid.uuid4()

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

    _thread_local.url = url
    print(f"[HTTPConnection.send] Request ID: {_thread_local.request_id}, URL: {url}")

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

    print(
        f"[HTTPResponseWrapper] Intercepting response for request ID: {_thread_local.request_id if hasattr(_thread_local, 'request_id') else 'N/A'}")
    fp = sock.makefile("rb", buffering=0)
    temp_file = tempfile.TemporaryFile()

    # Read up through the end of the header block.
    while True:
        line = fp.readline(65537)
        temp_file.write(line)
        if not line or line == b"\r\n":
            break

    temp_file.seek(0)
    content_length = None
    transfer_encoding = None
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

    # TODO: What if the connection times out or is closed early?
    if content_length is not None:
        to_read = content_length
        while to_read > 0:
            chunk = fp.read(min(2048, to_read))
            temp_file.write(chunk)
            to_read -= len(chunk)

    elif transfer_encoding == b"chunked":
        while True:
            chunk_size_line = fp.readline()
            temp_file.write(chunk_size_line)
            try:
                chunk_size = int(chunk_size_line.split(b";", 1)[0].strip(), 16)
            except ValueError:
                break
            if chunk_size == 0:
                temp_file.write(fp.read(2))  # Read the trailing \r\n
                break
            to_read = chunk_size + 2  # include trailing \r\n
            while to_read > 0:
                chunk = fp.read(min(2048, to_read))
                temp_file.write(chunk)
                to_read -= len(chunk)

    temp_file.seek(0)  # Reset file pointer for reading
    print(f"[HTTPResponseWrapper] Response written to temporary file")
    print(f"[HTTPResponseWrapper] Full response preview:\n{temp_file.read()!r}\n")
    temp_file.seek(0)
    _original_httpresponse_init(self, sock=FakeSocket(temp_file.read()), debuglevel=debuglevel, method=method, url=url)
    temp_file.close()

http.client.HTTPResponse.__init__ = httpresponse_init


_original_httpconnection_putrequest = http.client.HTTPConnection.putrequest

def logging_putrequest(self, method, url, *args, **kwargs):
    print(f"[HTTPConnection.putrequest] Method: {method}, URL: {url}")
    return _original_httpconnection_putrequest(self, method, url, *args, **kwargs)


# Patch
http.client.HTTPConnection.putrequest = logging_putrequest
