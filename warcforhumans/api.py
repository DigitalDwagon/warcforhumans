import io
import random
import string
import sys
import uuid
from datetime import datetime, timezone
from importlib.metadata import version
from io import BufferedRandom
from socket import socket
from ssl import SSLSocket

from warcforhumans.compression import Compressor


class WARCRecord:
    WARC_RECORD_ID = "WARC-Record-ID"
    CONTENT_LENGTH = "Content-Length"
    WARC_DATE = "WARC-Date"
    WARC_TYPE = "WARC-Type"
    CONTENT_TYPE = "Content-Type"
    CONTENT_HTTP_REQUEST = "application/http;msgtype=request"
    CONTENT_HTTP_RESPONSE = "application/http;msgtype=response"
    WARC_CONCURRENT_TO = "WARC-Concurrent-To"
    WARC_BLOCK_DIGEST = "WARC-Block-Digest"
    WARC_PAYLOAD_DIGEST = "WARC-Payload-Digest"
    WARC_IP_ADDRESS = "WARC-IP-Address"
    WARC_REFERS_TO = "WARC-Refers-To"
    WARC_REFERS_TO_TARGET_URI = "WARC-Refers-To-Target-URI"
    WARC_REFERS_TO_DATE = "WARC-Refers-To-Date"
    WARC_TARGET_URI = "WARC-Target-URI"
    WARC_TRUNCATED = "WARC-Truncated"
    WARC_WARCINFO_ID = "WARC-Warcinfo-ID"
    WARC_FILENAME = "WARC-Filename"
    WARC_PROFILE = "WARC-Profile"
    WARC_IDENTIFIED_PAYLOAD_TYPE = "WARC-Identified-Payload-Type"
    WARC_SEGMENT_NUMBER = "WARC-Segment-Number"
    WARC_SEGMENT_ORIGIN_ID = "WARC-Segment-Origin-ID"
    WARC_SEGMENT_TOTAL_LENGTH = "WARC-Segment-Total-Length"
    WARC_PROTOCOL = "WARC-Protocol" # https://github.com/iipc/warc-specifications/issues/42
    WARC_CIPHER_SUITE = "WARC-Cipher-Suite" # https://github.com/iipc/warc-specifications/issues/86

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
            self.set_header(WARCRecord.CONTENT_TYPE, content_type)

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

    def add_headers(self, headers: dict[str, list[str]]):
        self.headers.update(headers)

    def set_type(self, type: str):
        valid_warc_record_types = {"warcinfo", "response", "resource", "request", "metadata", "revisit", "conversion",
                                   "continuation"}
        if type not in valid_warc_record_types:
            raise ValueError(f"Invalid WARC record type: {type}")

        self.set_header(WARCRecord.WARC_TYPE, type)

    def set_content(self, content: bytes, type: str = None):
        self.content = content
        self.set_header(WARCRecord.CONTENT_LENGTH, str(len(content)))
        if type:
            self.set_header(WARCRecord.CONTENT_TYPE, type)

    def set_content_stream(self, stream: BufferedRandom, type: str = None, close: bool = False):
        if type:
            self.set_header(WARCRecord.CONTENT_TYPE, type)
        self.content = stream
        stream.seek(0, io.SEEK_END)
        self.set_header(WARCRecord.CONTENT_LENGTH, str((stream.tell())))
        self._close_content_stream = close

    def date_now(self):
        self.set_header(WARCRecord.WARC_DATE, datetime.now(timezone.utc).isoformat(timespec='seconds'))

    def get_id(self) -> str:
        if WARCRecord.WARC_RECORD_ID not in self.headers:
            self.set_header(WARCRecord.WARC_RECORD_ID, f"<{str(uuid.uuid4().urn)}>")
        return self.headers[WARCRecord.WARC_RECORD_ID][0]

    def get_type(self) -> str | None:
        return self.headers[WARCRecord.WARC_TYPE][0]

    def add_headers_for_socket(self, sock: socket):
        self.set_header(WARCRecord.WARC_IP_ADDRESS, sock.getpeername()[0])

        if isinstance(sock, SSLSocket):
            encryption_protocol, version = sock.cipher()[1].split("v")
            self.add_header(WARCRecord.WARC_PROTOCOL, encryption_protocol.lower() + "/" + version)
            self.add_header(WARCRecord.WARC_CIPHER_SUITE, sock.cipher()[0])

    def serialize_stream(self):
        if self.content is None:
            raise ValueError("Content is not set")

        mandatory_headers = [WARCRecord.WARC_RECORD_ID, WARCRecord.CONTENT_LENGTH, WARCRecord.WARC_DATE, WARCRecord.WARC_TYPE]
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
    def __init__(self, file_path: str, create_warcinfo: bool = True, warcinfo_headers = None, compressor: Compressor = None, software: str = ""):
        self._warcinfo_record = None
        self._pending_records = []

        if not compressor:
            self._compressor = Compressor()
        else:
            self._compressor = compressor

        self.file_path = file_path + ".warc" + self._compressor.file_extension()
        self.file = open(self.file_path, "ab")
        self._compressor.start(self.file)

        if create_warcinfo:
            self.create_warcinfo_record(headers=warcinfo_headers,software=software)

    def create_warcinfo_record(self, software: str = "", headers: dict[str, str] = None):
        if headers is None:
            headers = {}

        warc_record = WARCRecord("warcinfo", "application/warc-fields")
        warc_record.set_header(WARCRecord.WARC_FILENAME, self.file.name)

        headers["software"] = f"warcforhumans/{version("warcforhumans")} {software}"
        headers["format"] = "WARC File Format 1.1"
        headers["conformsTo"] = "https://bibnum.bnf.fr/WARC/WARC_ISO_28500_version1-1_latestdraft.pdf"
        headers["python-version"] = "python/" + sys.version.replace("\n", "")

        body = str()
        for key, value in headers.items():
            body += f"{key}: {value}\r\n"

        warc_record.set_content(body.encode("utf-8"))
        self.write_record(warc_record, write_warcinfo_header=False)
        self._warcinfo_record = warc_record

    def write_record(self, record: WARCRecord, write_warcinfo_header: bool = True):
        if self._warcinfo_record is not None and write_warcinfo_header:
            record.set_header(WARCRecord.WARC_WARCINFO_ID, self._warcinfo_record.get_id())

        self._compressor.write_record(record, self.file)

        record.close()
        self.file.flush()

    def close(self):
        self.file.close()

class WARCWriter:
    def __init__(self,
                 prefix: str,
                 compressor: Compressor = None,
                 rotate_mb: int = 15*1024,
                 software: str = "",
                 warcinfo_headers: dict[str, str] = None,
                 revisit: bool = True
                 ):
        self.warc_file = None
        self.compressor = compressor if compressor else Compressor()
        self.prefix = prefix
        self.rotate_mb = rotate_mb
        self.pending_records: list[WARCRecord] = []
        self.software = software
        self.warcinfo_headers = warcinfo_headers
        self.files_made = 0
        self.closed = False
        self.revisit = revisit
        if revisit:
            self.revisit_cache: dict[str, tuple[str, str, str]] = {} # payload-digest -> (warc-record-id, warc-date, warc-target-uri)

    def _create_file(self, rotate = True):
        if (    self.warc_file
                and rotate
                and self.rotate_mb > 0
                and self.warc_file.file.tell() >= self.rotate_mb * 1024 * 1024
           ):
            self.warc_file.close()
            self.warc_file = None
        if not self.warc_file:
            template_data = {"date": datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
                             "number": f"{self.files_made:05d}",
                             "serial": ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}
            name = string.Template(self.prefix).substitute(template_data)
            self.warc_file = WARCFile(name, compressor=self.compressor, software=self.software, warcinfo_headers=self.warcinfo_headers)
            self.files_made += 1

    def flush_pending(self):
        temp = self.pending_records
        self.pending_records = []
        self.write_records(temp)

    def discard_pending(self):
        self.pending_records = []

    def discard(self, record_id):
        for record in self.pending_records:
            if record.get_id() == record_id:
                self.pending_records.remove(record)


    def write_record(self, record: WARCRecord, rotate = True):
        if self.closed:
            raise ValueError("WARCWriter is closed")

        self._create_file()
        if self.revisit and record.get_type() == "response":
            payload_digest = record.headers.get(WARCRecord.WARC_PAYLOAD_DIGEST, [None])[0]
            date = record.headers.get(WARCRecord.WARC_DATE, [None])[0]
            target_uri = record.headers.get(WARCRecord.WARC_TARGET_URI, [None])[0]
            record_id = record.get_id()
            if payload_digest and date and target_uri:
                self.revisit_cache[payload_digest] = (record_id, date, target_uri)

        self.warc_file.write_record(record)

    def check_for_revisit(self, payload_digest: str) -> tuple[bool, dict[str, list[str]]]:
        if not self.revisit:
            return False, {}

        if not payload_digest in self.revisit_cache:
            return False, {}

        record_id, date, target_uri = self.revisit_cache[payload_digest]
        headers = {
            WARCRecord.WARC_REFERS_TO: [record_id],
            WARCRecord.WARC_REFERS_TO_DATE: [date],
            WARCRecord.WARC_REFERS_TO_TARGET_URI: [target_uri]
        }
        return True, headers


    def write_records(self, records: list[WARCRecord], rotate_between=False):
        for record in records:
            self.write_record(record, rotate=rotate_between)

    def close(self):
        if not self.closed:
            self.flush_pending()
            if self.warc_file:
                self.warc_file.close()
            self.closed = True
