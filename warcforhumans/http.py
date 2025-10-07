import http.client
import io
import socket
import threading
import uuid

_thread_local = threading.local()

# Keep reference to original send
_original_httpconnection_send = http.client.HTTPConnection.send

def logging_send(self, data):
    # data is bytes
    preview = data#[:512]  # preview first 512 bytes
    print(f"[HTTPConnection.send] {len(data)} bytes, preview:\n{preview!r}\n")
    _thread_local.request_id = f"<urn:uuid:{uuid.uuid4()}>"
    return _original_httpconnection_send(self, data)

# Patch
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

class HTTPResponseWrapper(http.client.HTTPResponse):
    def __init__(self, sock, debuglevel=0, method=None, url=None):
        print(f"[HTTPResponseWrapper] Intercepting response for request ID: {_thread_local.request_id if hasattr(_thread_local, 'request_id') else 'N/A'}")

        fp = sock.makefile("rb", buffering=0)
        data = b""
        while True:
            line = fp.readline(65537)
            data += line
            if not line or line == b"\r\n":
                break

        # get the value of the content-length header if present
        content_length = None
        transfer_encoding = None
        for header in data.split(b"\r\n"):
            if header.lower().startswith(b"content-length:"):
                try:
                    content_length = int(header.split(b":", 1)[1].strip())
                    break
                except ValueError:
                    pass
            elif header.lower().startswith(b"transfer-encoding:"):
                transfer_encoding = header.split(b":", 1)[1].strip().lower()
                break
        #print(data)

        if content_length is not None:
            to_read = content_length
            while to_read > 0:
                chunk = fp.read(2048)
                data += chunk
                to_read -= len(chunk)

        if transfer_encoding == b"chunked":
            while True:
                chunk_size_line = fp.readline()
                data += chunk_size_line
                try:
                    chunk_size = int(chunk_size_line.split(b";", 1)[0].strip(), 16)
                except ValueError:
                    break
                if chunk_size == 0:
                    #print("starting to read last rn")
                    data += fp.read(2)
                    break
                to_read = chunk_size
                while to_read > 0:
                    chunk = fp.read(2048)
                    data += chunk
                    to_read -= len(chunk)

        print(f"[HTTPResponseWrapper] {len(data)} bytes:\n{data!r}\n")
        _original_httpresponse_init(self, sock=FakeSocket(data), debuglevel=debuglevel, method=method, url=url)

http.client.HTTPResponse.__init__ = HTTPResponseWrapper.__init__
