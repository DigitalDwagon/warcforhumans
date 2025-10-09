import io
import sys
import uuid
from io import BytesIO, BufferedRandom
from datetime import datetime
from socket import socket
from ssl import SSLSocket


class WARCRecord:
    def __init__(self, type: str = None, content_type: str = None):
        # https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1-annotated/#warc-type-mandatory

        self.headers: dict[str, list[str]] = {}
        self.content = None
        self._close_content_stream : bool = False

        if type is not None:
            self.set_type(type)
            self.get_id()
            self.date_now()

        if content_type is not None:
            self.set_header("Content-Type", content_type)

    def set_header(self, key: str, value):
        if isinstance(value, list):
            self.headers[key] = value
        else:
            self.headers[key] = [value]

    def add_header(self, key: str, value: str):
        if key in self.headers:
            self.headers[key].append(value)
        else:
            self.headers[key] = [value]

    def set_headers(self, headers: dict[str, str]):
        for key, value in headers.items():
            self.set_header(key, value)

    def set_type(self, type: str):
        valid_warc_record_types = {"warcinfo", "response", "resource", "request", "metadata", "revisit", "conversion",
                                   "continuation"}
        if type not in valid_warc_record_types:
            raise ValueError(f"Invalid WARC record type: {type}")

        self.set_header("WARC-Type", type)

    def set_content(self, content: bytes):
        self.content = content
        self.set_header("Content-Length", str(len(content)))

    def set_content_stream(self, stream: BufferedRandom, close: bool = False):
        self.content = stream
        stream.seek(0, io.SEEK_END)
        self.set_header("Content-Length", str((stream.tell())))
        self._close_content_stream = close

    def date_now(self):
        self.set_header("WARC-Date", datetime.now().isoformat())

    def get_id(self) -> str:
        if "WARC-Record-ID" not in self.headers:
            self.set_header("WARC-Record-ID", f"<{str(uuid.uuid4().urn)}>")
        return self.headers["WARC-Record-ID"][0]


    def add_headers_for_socket(self, sock: socket):
        self.set_header("WARC-IP-Address", sock.getpeername()[0])

        if isinstance(sock, SSLSocket):
            encryption_protocol, version = sock.cipher()[1].split("v")
            self.add_header("WARC-Protocol", encryption_protocol.lower() + "/" + version)
            self.add_header("WARC-Cipher-Suite", sock.cipher()[0])

    def serialize_stream(self):
        if self.content is None:
            raise ValueError("Content is not set")

        mandatory_headers = ["WARC-Record-ID", "Content-Length", "WARC-Date", "WARC-Type"]
        for header in mandatory_headers:
            if header not in self.headers:
                raise ValueError(f"Mandatory header {header} is missing")

        yield b"WARC/1.1\r\n"
        for key, value in self.headers.items():
            for v in value:
                yield f"{key}: {v}\r\n".encode("utf-8")
        yield b"\r\n"

        # Stream the content in chunks
        if isinstance(self.content, bytes):
            yield self.content
        else:
            chunk_size = 8192  # Define a chunk size
            self.content.seek(0)
            while True:
                chunk = self.content.read(chunk_size)
                if not chunk:
                    break
                yield chunk

        yield b"\r\n\r\n"

    def close(self):
        if self._close_content_stream and hasattr(self.content, 'close'):
            self.content.close()

class WARCFile:
    def __init__(self, file_path: str, create_warcinfo: bool = True):
        self.file_path = file_path
        self.file = open(file_path, "ab")
        self._warcinfo_record = None
        self._pending_records = []

        if create_warcinfo:
            self.create_warcinfo_record()

    def create_warcinfo_record(self, software: str = "", headers: dict[str, str] = None):
        if headers is None:
            headers = {}

        warc_record = WARCRecord("warcinfo", "application/warc-fields")
        warc_record.set_header("WARC-Filename", self.file.name)

        headers["software"] = "warcforhumans/0.1-alpha " + software
        headers["format"] = "WARC File Format 1.1"
        headers["conformsTo"] = "https://bibnum.bnf.fr/WARC/WARC_ISO_28500_version1-1_latestdraft.pdf"
        headers["python-version"] = "python/" + sys.version.replace("\n", "")

        body = str()
        for key, value in headers.items():
            body += f"{key}: {value}\r\n"

        warc_record.set_content(body.encode("utf-8"))
        self.write_record(warc_record, write_warcinfo_header=False)

    def write_record(self, record: WARCRecord, write_warcinfo_header: bool = True):
        if self._warcinfo_record is not None and write_warcinfo_header:
            record.set_header("WARC-Warcinfo-ID", self._warcinfo_record.get_id())

        for chunk in record.serialize_stream():
            self.file.write(chunk)
        record.close()
        self.file.flush()

    def next_request_pair(self, request: WARCRecord, response: WARCRecord):
        self.flush_pending()

        self._pending_records.append(request)
        self._pending_records.append(response)

    def discard_last(self):
        self._pending_records = []

    def flush_pending(self):
        if self._pending_records:
            for record in self._pending_records:
                self.write_record(record)
            self._pending_records = []

    def close(self):
        self.flush_pending()
        self.file.close()