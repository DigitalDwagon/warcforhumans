import hashlib
import socket
import ssl
import tempfile
import typing
from collections.abc import Generator
from io import BufferedRandom
from typing import override

import h11
from _hashlib import HASH
from urllib3.connection import _ssl_wrap_socket_and_match_hostname

import warcforhumans.api as warc
from warcforhumans.api import WARCWriter, WARCRecord
from warcforhumans.capture import util

CHUNK_SIZE = 2048

class ConnectionInfo(typing.NamedTuple):
    scheme: str
    host: str
    port: int
    connect_timeout: float | None = None
    read_timeout: float | None = None
    verify: bool | str | None = None
    cert: typing.Any | None = None
    proxies: typing.Any | None = None
    socket_options: util._TYPE_SOCKET_OPTIONS = []

class SecureConnectionOptions(typing.NamedTuple):
    cert_reqs: int | str | None = None
    assert_hostname: None | str | typing.Literal[False] = None
    assert_fingerprint: str | None = None
    server_hostname: str | None = None
    ssl_context: ssl.SSLContext | None = None
    ca_certs: str | None = None
    ca_cert_dir: str | None = None
    ca_cert_data: None | str | bytes = None
    ssl_minimum_version: int | None = None
    ssl_maximum_version: int | None = None
    ssl_version: int | str | None = None  # Deprecated in urllib3
    cert_file: str | None = None
    key_file: str | None = None
    key_password: str | None = None

class H11Connection:
    def __init__(self,
                 info: ConnectionInfo,
                 *,
                 secure_options: SecureConnectionOptions | None = None,
                 throwaway: bool = False
                 ) -> None:
        self.info: ConnectionInfo = info
        self.throwaway: bool = throwaway

        self.closed: bool = False
        self.is_verified: bool = False
        self.sock: socket.socket = self._create_socket(secure_options)
        self.conn: h11.Connection = h11.Connection(our_role=h11.CLIENT)

    def _create_socket(self, secure_options: SecureConnectionOptions | None) -> socket.socket:
        sock: socket.socket = socket.create_connection((self.info.host, self.info.port), timeout=self.info.connect_timeout)
        sock.settimeout(self.info.read_timeout)

        for level, optname, value in self.info.socket_options:
            sock.setsockopt(level, optname, value)

        if self.info.scheme == "https":
            if not secure_options:
                secure_options = SecureConnectionOptions()

            # TODO - it would be nice to not rely on urllib3 here
            wrapped = _ssl_wrap_socket_and_match_hostname(
                sock,
                cert_reqs=secure_options.cert_reqs,
                ssl_version=secure_options.ssl_version,
                ssl_minimum_version=secure_options.ssl_minimum_version,
                ssl_maximum_version=secure_options.ssl_maximum_version,
                cert_file=secure_options.cert_file,
                key_file=secure_options.key_file,
                key_password=secure_options.key_password,
                ca_certs=secure_options.ca_certs,
                ca_cert_dir=secure_options.ca_cert_dir,
                ca_cert_data=secure_options.ca_cert_data,
                assert_hostname=secure_options.assert_hostname,
                assert_fingerprint=secure_options.assert_fingerprint,
                server_hostname=secure_options.server_hostname or self.info.host,
                ssl_context=secure_options.ssl_context,
            )

            sock = wrapped.socket
            self.is_verified = wrapped.is_verified

        return sock

    def send_event(self, event: h11.Event) -> None:
        b = self.conn.send(event)
        self.sock.sendall(b)

    def next_event(self, chunk_size: int) -> h11.Event | type[h11.PAUSED]:
        while True:
            event = self.conn.next_event()
            if isinstance(event, h11.NEED_DATA):
                bytes_received = self.sock.recv(chunk_size)
                self.conn.receive_data(bytes_received)
                continue

            if isinstance(event, h11.ConnectionClosed):
                self.close()

            if self.throwaway and isinstance(event, h11.EndOfMessage):
                self.close()

            assert event is h11.PAUSED or isinstance(event, h11.Event) # h11.NEED_DATA can never make it out of the loop, but this makes pyright happy.
            return event

    def close(self) -> None:
        self.conn.send(h11.ConnectionClosed())
        self.sock.close()

    def start_next_cycle(self) -> None:
        our_state = self.conn.our_state
        their_state = self.conn.their_state

        if our_state != h11.IDLE and our_state != h11.DONE:
            raise h11.LocalProtocolError(f"connection not in a state where the next cycle can be started: {self.conn.states}")

        if our_state == h11.IDLE and their_state == h11.IDLE:
            # next cycle already started
            return

        if our_state == h11.DONE and not their_state == h11.DONE:
            _ = self.events_until_end(CHUNK_SIZE)

        # states should be [DONE, DONE] if it made it this far
        # todo: verify that this functions correctly
        self.conn.start_next_cycle()

    def events_until_end(self, chunk_size: int) -> Generator[h11.Event | type[h11.PAUSED]]:
        while True:
            event = self.next_event(chunk_size)
            yield event
            if isinstance(event, h11.EndOfMessage):
                return


class WARCWritingH11Connection(H11Connection):
    def __init__(self,
                 info: ConnectionInfo,
                 warc_writer: WARCWriter,
                 secure_options: SecureConnectionOptions | None = None,
                 throwaway: bool = False
                 ) -> None:
        super().__init__(info, secure_options=secure_options, throwaway=throwaway)

        self.request_record: WARCRecord | None = None
        self.response_record: WARCRecord | None = None
        self.response_payload_hash: HASH | None = None
        self.response_file: BufferedRandom | None = None
        self.warc_writer: WARCWriter = warc_writer


    @override
    def send_event(self, event: h11.Event) -> None:
        if isinstance(event, h11.Request):
            # todo check if there's another wip record
            if self.info.scheme != "http" and self.info.scheme != "https":
                raise ValueError("Scheme for connection is not http or https.")

            url: str = self.info.scheme + "://" + self.info.host

            if self.info.scheme == "https" and self.info.port != 443:
                url += ":" + str(self.info.port)
            elif self.info.scheme == "http" and self.info.port != 80:
                url += ":" + str(self.info.port)

            url += event.target.decode("iso-8859-1")

            request_record: WARCRecord = WARCRecord("request", url=url, content_type=WARCRecord.CONTENT_HTTP_REQUEST, sock=self.sock)
            request_record.add_header(WARCRecord.WARC_PROTOCOL, WARCRecord.HTTP_1_1)
            request_record.date()
            self.request_record = request_record

        if self.request_record is None:
            raise RuntimeError("You tried to send an event, but no WARC request record was open. Your first event should be an h11.Request.")


        b: bytes | None = self.conn.send(event)

        if b is not None:
            self.sock.sendall(b)
            self.request_record.partial_content(b, finish=isinstance(event, h11.EndOfMessage))

    @override
    def next_event(self, chunk_size: int) -> h11.Event | type[h11.PAUSED]:
        if self.request_record is None:
            raise RuntimeError("Started receiving a response, but there's no open request record.")

        if not self.response_record:
            # todo make sure there's a request record and no opened response record, etc
            self.response_record = WARCRecord(record_type="response", content_type=WARCRecord.CONTENT_HTTP_RESPONSE, url=self.request_record.headers[WARCRecord.WARC_TARGET_URI][0], sock=self.sock)
            self.response_record.set_header(WARCRecord.WARC_DATE, self.request_record.headers[WARCRecord.WARC_DATE][0])

            self.response_file = tempfile.TemporaryFile()
            self.response_payload_hash = hashlib.sha1()


        while True:
            event = self.conn.next_event()
            if isinstance(event, h11.NEED_DATA):
                # This will read bytes past the end of the HTTP response. Extra bytes will be truncated when EndOfMessage is reached.
                bytes_received = self.sock.recv(chunk_size)
                self.conn.receive_data(bytes_received)

                if self.response_file is None:
                    raise RuntimeError("No open response file (when writing response content)")

                _ = self.response_file.write(bytes_received)
                continue
            break


        if isinstance(event, h11.Data):
            if self.response_payload_hash is not None:
                self.response_payload_hash.update(event.data)

        if isinstance(event, h11.ConnectionClosed):
            self.sock.close()
            self.closed = True

        if isinstance(event, h11.Response):
            self.response_record.add_header(WARCRecord.WARC_PROTOCOL, f"http/{event.http_version.decode()}")


        if isinstance(event, h11.EndOfMessage):
            if not self.response_file:
                raise RuntimeError("Response file content is none when trying to finish a response message.")

            # Truncate any bytes that came after the end of the HTTP response
            # trailing_data contains bytes that were not consumed by h11 for this message
            excess_bytes = len(self.conn.trailing_data[0])
            if excess_bytes > 0:
                self.response_file.seek(0, 2) # seek to end
                file_size = self.response_file.tell()
                new_size = file_size - excess_bytes
                self.response_file.truncate(new_size)

            if self.response_payload_hash is None:
                raise RuntimeError("No payload hash when trying to finish response.")
            self.response_record.set_header(WARCRecord.WARC_PAYLOAD_DIGEST, warc.hash_to_string(self.response_payload_hash))

            revisit, headers = self.warc_writer.check_for_revisit(self.response_record.headers[WARCRecord.WARC_PAYLOAD_DIGEST][0])

            if revisit:
                self.response_record.add_headers(headers)
                self.response_record.set_type("revisit")

                # grab up to the first \r\n\r\n (header block)
                self.response_file.seek(0)  # ensure we are back at the start
                header_content = b""
                while True:
                    line = self.response_file.readline(CHUNK_SIZE)
                    header_content += line
                    if not line or line == b"\r\n":
                        break

                self.response_record.set_content(header_content)
            else:
                self.response_record.set_content(self.response_file, close = True)

            self.response_record.concurrent(self.request_record)
            self.warc_writer.pending_records.append(self.response_record)
            self.warc_writer.pending_records.append(self.request_record)
            self.warc_writer.flush_pending()

            self.request_record = None
            self.response_record = None
            self.response_payload_hash = None
            self.response_file = None

            self.start_next_cycle()

        return event

    @override
    def close(self) -> None:
        if self.conn.our_state != h11.IDLE or self.conn.their_state != h11.IDLE:
            self.events_until_end(CHUNK_SIZE)

        self.sock.close()