import base64
import hashlib
import io
import random
import string
import sys
import uuid
from datetime import datetime, timezone
from importlib.metadata import version
from socket import socket
from ssl import SSLSocket
from typing import Iterator, BinaryIO

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

    def __init__(self, record_type: str = None, content_type: str = None, url: str = None, sock: socket = None):
        """
        Creates a new WARC record, with a random ID and the date set to the current timestamp.
        :param record_type: The type of WARC record. Equivalent to ``set_type``
        :param content_type: The ``Content-Type`` of the WARC record
        :param url: The URL of the WARC record
        :param sock: Add headers based on the socket that this record was captured from. Equivalent to
         ``add_headers_for_socket``
        """
        # https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1-annotated/#warc-type-mandatory

        self.headers: dict[str, list[str]] = {}
        self.content = None
        self._close_content_stream : bool = False

        self.get_id()
        self.date_now()

        if record_type is not None:
            self.set_type(record_type)

        if content_type is not None:
            self.set_header(WARCRecord.CONTENT_TYPE, content_type)

        if url is not None:
            self.set_header(WARCRecord.WARC_TARGET_URI, url)

        if sock is not None:
            self.add_headers_for_socket(sock)

    def set_header(self, key: str, value):
        """
        Sets a header on the record, **overwriting** the value if one is already set.
        :param key: Header name
        :param value: Header value
        :return:
        """
        if isinstance(value, list):
            self.headers[key] = value
        else:
            self.headers[key] = [value]

    def add_header(self, key: str, value: str):
        """
        Adds a header to the record, **repeating the header** if the header is already set.
        :param key: Header name
        :param value: Header value
        :return:
        """
        if key in self.headers:
            self.headers[key].append(value)
        else:
            self.headers[key] = [value]

    def add_headers(self, headers: dict[str, list[str]]):
        self.headers.update(headers)

    def set_type(self, record_type: str):
        valid_warc_record_types = {"warcinfo", "response", "resource", "request", "metadata", "revisit", "conversion",
                                   "continuation"}
        if record_type not in valid_warc_record_types:
            raise ValueError(f"Invalid WARC record type: {record_type}")

        self.set_header(WARCRecord.WARC_TYPE, record_type)

    def set_content(self, content: bytes | BinaryIO, content_type: str = None, block_digest = None, close: bool = False):
        """
        Sets the body content of the WARC record.
        :param content: The content of the record, as bytes or a seekable file object.
        :param content_type: The ``Content-Type`` to set for the record.
        :param block_digest: A hash of content (as a hash object), used as the ``WARC-Block-Digest``. If not set, one
         will be generated with SHA-512.
        :param close: If content is a file object, whether it should be closed after the record is written.
        :return:
        """
        if content_type:
            self.set_header(WARCRecord.CONTENT_TYPE, content_type)

        if isinstance(content, bytes):
            self._set_content_bytes(content, block_digest=block_digest)
        elif hasattr(content, "read") and hasattr(content, "seek"):
            self._set_content_stream(content, close=close, block_digest=block_digest)
        else:
            raise ValueError("Unknown record content - expected a bytes or BufferedRandom like object")


    def _set_content_bytes(self, content: bytes, block_digest = None):
        self.content = content
        self.set_header(WARCRecord.CONTENT_LENGTH, str(len(content)))

        if not block_digest:
            block_digest = hashlib.sha512(content)
        self.set_header(WARCRecord.WARC_BLOCK_DIGEST, hash_to_string(block_digest))


    def _set_content_stream(self, stream: BinaryIO, close: bool = False, block_digest = None):
        self.content = stream
        stream.seek(0, io.SEEK_END)
        self.set_header(WARCRecord.CONTENT_LENGTH, str((stream.tell())))
        self._close_content_stream = close

        if not block_digest:
            block_digest = hashlib.sha512()
            stream.seek(0)
            while chunk := stream.read(2048):
                block_digest.update(chunk)

        self.set_header(WARCRecord.WARC_BLOCK_DIGEST, hash_to_string(block_digest))

    def date_now(self):
        """
        Sets the timestamp of the WARC to the current time.
        :return:
        """
        self.set_header(WARCRecord.WARC_DATE, datetime.now(timezone.utc).isoformat(timespec='seconds'))

    def get_id(self) -> str:
        """
        Gets the ID of the record. If there isn't one already, one will be randomly generated.
        :return:
        """
        if WARCRecord.WARC_RECORD_ID not in self.headers:
            self.set_header(WARCRecord.WARC_RECORD_ID, f"<{str(uuid.uuid4().urn)}>")
        return self.headers[WARCRecord.WARC_RECORD_ID][0]

    def get_type(self) -> str | None:
        return self.headers[WARCRecord.WARC_TYPE][0]

    def add_headers_for_socket(self, sock: socket):
        """
        Sets headers of the WARC record based on the given socket. ``WARC-IP-Address`` will be set for all sockets.
         For an SSLSocket,``WARC-Protocol`` and ``WARC-Cipher-Suite`` will also be set to document the encryption used.
        :param sock: The socket that this record was captured from
        :return:
        """
        self.set_header(WARCRecord.WARC_IP_ADDRESS, sock.getpeername()[0])

        if isinstance(sock, SSLSocket):
            encryption_protocol, protocol_version = sock.cipher()[1].split("v")
            self.add_header(WARCRecord.WARC_PROTOCOL, encryption_protocol.lower() + "/" + protocol_version)
            self.add_header(WARCRecord.WARC_CIPHER_SUITE, sock.cipher()[0])

    def concurrent(self, record):
        """
        Sets ``WARC-Concurrent-To`` headers on both given records, pointing at each other.
        :param record: The other record.
        :return:
        """
        self.set_header(WARCRecord.WARC_CONCURRENT_TO, record.get_id())
        record.set_header(WARCRecord.WARC_CONCURRENT_TO, self.get_id())

    def serialize_stream(self) -> Iterator[bytes]:
        """
        Serializes this WARC record as bytes and yields it in chunks.
        :return: Iterator[bytes] of the serialized record chunks
        """

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

        if isinstance(self.content, bytes):
            yield self.content
        else:
            chunk_size = 8192 # todo we should use a set chunk size everywhere
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
    def __init__(self, file_path: str, create_warcinfo: bool = True, warcinfo_fields = None, compressor: Compressor = None, software: str = ""):
        """
        Creates a new WARCFile to write WARC records to.
        :param file_path: Where the file should go, without ``.warc``
        :param create_warcinfo: Whether to create a warcinfo record for this file
        :param warcinfo_fields: Fields to add to the warcinfo record.
        :param compressor: ``Compressor`` to use for the file. The WARC will be uncompressed if not specified.
        :param software: The name of the software to add to warcinfo. warcforhumans will add its own name and version
         to the front of the provided string
        """
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
            self.create_warcinfo_record(fields=warcinfo_fields,software=software)

    def create_warcinfo_record(self, software: str = "", fields: dict[str, str] = None):
        """
        Creates a warcinfo record for the WARC file.
        :param software: The name of the software to add to warcinfo. warcforhumans will add its own name and version
         to the front of the provided string
        :param fields: Fields to add to the warcinfo record.
        :return:
        """
        if fields is None:
            fields = {}

        warc_record = WARCRecord("warcinfo", "application/warc-fields")
        warc_record.set_header(WARCRecord.WARC_FILENAME, self.file.name)

        fields["software"] = f"warcforhumans/{version("warcforhumans")} {software}"
        fields["format"] = "WARC File Format 1.1"
        fields["conformsTo"] = "https://bibnum.bnf.fr/WARC/WARC_ISO_28500_version1-1_latestdraft.pdf"
        fields["python-version"] = "python/" + sys.version.replace("\n", "")

        body = str()
        for key, value in fields.items():
            body += f"{key}: {value}\r\n"

        warc_record.set_content(body.encode("utf-8"))
        self.write_record(warc_record, write_warcinfo_header=False)
        self._warcinfo_record = warc_record

    def write_record(self, record: WARCRecord, write_warcinfo_header: bool = True):
        """
        Write a record to the file.
        :param record: The record to write
        :param write_warcinfo_header: Whether to write a ``WARC-Warcinfo-ID`` header for this record (if a warcinfo
         record for this file exists).
        :return:
        """
        if self._warcinfo_record is not None and write_warcinfo_header:
            record.set_header(WARCRecord.WARC_WARCINFO_ID, self._warcinfo_record.get_id())

        self._compressor.write_record(record, self.file)

        record.close()
        self.file.flush()

    def close(self):
        self.file.close()

class WARCWriter:
    def __init__(self,
                 template: str,
                 compressor: Compressor = None,
                 rotate_mb: int = 15*1024,
                 software: str = "",
                 warcinfo_fields: dict[str, str] = None,
                 revisit: bool = True
                 ):
        """
        Creates a WARCWriter, to manage writing WARC records.
        :param template: Name template for the created WARC files. Available variables:
            ``$date`` - the datetime the file was started at (``yyyymmddHHMMSS``)
            ``$number`` - the number of files made by this writer, starting from 00000
            ``$serial`` - 8 character random string
        :param compressor: ``Compressor`` to use for the file. The WARC will be uncompressed if not specified.
        :param rotate_mb: Automatically start a new file when the old one gets above this size. Set to -1 to never start
         a new file.
        :param software: The name of the software to add to warcinfo. warcforhumans will add its own name and version
         to the front of the provided string
        :param warcinfo_fields: Fields to add to the warcinfo record.
        :param revisit: Whether to keep track of the information necessary (in memory) for ``check_for_revisit``
        """
        self.warc_file = None
        self.compressor = compressor if compressor else Compressor()
        self.template = template
        self.rotate_mb = rotate_mb
        self.pending_records: list[WARCRecord] = []
        self.software = software
        self.warcinfo_fields = warcinfo_fields
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
            name = string.Template(self.template).substitute(template_data)
            self.warc_file = WARCFile(name, compressor=self.compressor, software=self.software, warcinfo_fields=self.warcinfo_fields)
            self.files_made += 1

    def flush_pending(self):
        """
        Write records that have been finished but not yet written.
        :return:
        """
        temp = self.pending_records
        self.pending_records = []
        self.write_records(temp)

    def discard_pending(self):
        """
        Discard records that have been finished but not yet written.
        :return:
        """
        self.pending_records = []

    def discard(self, record_id):
        """
        Discard a specific pending record by its ID
        :param record_id: ID of the record to discard
        :return:
        """
        for record in self.pending_records:
            if record.get_id() == record_id:
                self.pending_records.remove(record)


    def write_record(self, record: WARCRecord, rotate = True):
        """
        Write a record to the current file.
        :param record: The record to write.
        :param rotate: If disabled, the writer will not start a new file before writing this record, even if it is above
         the rotation size. This can be useful to ensure that request/response pairs don't get split between files.
        :return:
        """
        if self.closed:
            raise ValueError("WARCWriter is closed")

        self._create_file(rotate=rotate)
        if self.revisit and record.get_type() == "response":
            payload_digest = record.headers.get(WARCRecord.WARC_PAYLOAD_DIGEST, [None])[0]
            date = record.headers.get(WARCRecord.WARC_DATE, [None])[0]
            target_uri = record.headers.get(WARCRecord.WARC_TARGET_URI, [None])[0]
            record_id = record.get_id()
            if payload_digest and date and target_uri:
                self.revisit_cache[payload_digest] = (record_id, date, target_uri)

        self.warc_file.write_record(record)

    def check_for_revisit(self, payload_digest: str) -> tuple[bool, dict[str, list[str]]]:
        """
        Checks whether a given payload digest has been seen before by this writer, and returns the necessary WARC
         headers for a revisit if the payload was seen. Will always return false if revisits have been disabled on this
         WARCWriter.
        :param payload_digest: The payload digest to search for
        :return: a tuple (boolean match found, dict of warc headers to add on a revisit)
        """
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
        """
        Write multiple records to the WARC file
        :param records: The records to write
        :param rotate_between: Whether the records to be written can be split between different WARC files
        :return:
        """
        for record in records:
            self.write_record(record, rotate=rotate_between)

    def close(self):
        if not self.closed:
            self.flush_pending()
            if self.warc_file:
                self.warc_file.close()
            self.closed = True

def hash_to_string(h) -> str:
    """
    Converts a hashlib hash object to a string for writing WARC digest headers.
    :param h: The hash to convert
    :return: A string like "sha1:AIKLJM2V2EOKR4WOIWUWRQTEMUN57P4D"
    """
    if h.name == "md5":
        # Typical encoding of md5 is lowercase base16
        # https://github.com/iipc/warc-specifications/issues/80#issuecomment-1637084423
        return f"{h.name}:{h.hexdigest()}"

    return f"{h.name}:{base64.b32encode(h.digest()).decode("utf-8")}"