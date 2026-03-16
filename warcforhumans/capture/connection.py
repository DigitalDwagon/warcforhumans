from math import inf
import typing
import socket
import ssl
from io import BufferedRandom
import tempfile
from typing import override
import hashlib

import h11
from _hashlib import HASH

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


class H11Connection:
    def __init__(self,
                 info: ConnectionInfo,
                 throwaway: bool = False
                 ) -> None:
        self.info: ConnectionInfo = info
        self.throwaway: bool = throwaway

        self.closed: bool = False

        #todo socket creation should be extracted to a method
        self.sock: socket.socket = socket.create_connection((info.host, info.port), timeout=info.connect_timeout)
        self.sock.settimeout(info.read_timeout)

        for level, optname, value in info.socket_options:
            self.sock.setsockopt(level, optname, value)

        if info.scheme == "https":
            if isinstance(info.verify, str):
                # todo custom paths not working
                ctx = ssl.create_default_context(capath=info.verify)
            elif isinstance(info.verify, bool) and info.verify:
                ctx = ssl.create_default_context()
                ctx.verify_mode = ssl.CERT_REQUIRED
            else:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            if info.cert:
                # todo not working
                if isinstance(info.cert, tuple) and len(info.cert) == 2:
                    ctx.load_cert_chain(certfile=info.cert[0], keyfile=info.cert[1])
                elif isinstance(info.cert, str):
                    ctx.load_cert_chain(certfile=info.cert)
                else:
                    raise ValueError(
                        "Invalid certificate format. Provide a path to the certificate or a tuple (certfile, keyfile).")

            self.sock = ctx.wrap_socket(self.sock, server_hostname=info.host)

        self.conn: h11.Connection = h11.Connection(our_role=h11.CLIENT)

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
        self.conn.start_next_cycle()


class WARCWritingH11Connection(H11Connection):
    def __init__(self,
                 info: ConnectionInfo,
                 warc_writer: WARCWriter,
                 throwaway: bool = False
                 ) -> None:
        super().__init__(info, throwaway)

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
            print(f"send: {b[:512]!r}")

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
                bytes_received = self.sock.recv(chunk_size)
                self.conn.receive_data(bytes_received)

                if self.response_file is None:
                    raise RuntimeError("No open response file (when writing response content)")

                _ = self.response_file.write(bytes_received)
                print(f"recv: {bytes_received[:512]!r}")
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

            if self.response_payload_hash is None:
                raise RuntimeError("No payload hash when trying to finish response.")
            self.response_record.set_header(WARCRecord.WARC_PAYLOAD_DIGEST, warc.hash_to_string(self.response_payload_hash))

            revisit, headers = self.warc_writer.check_for_revisit(self.response_record.headers[WARCRecord.WARC_PAYLOAD_DIGEST][0])

            if revisit:
                self.response_record.add_headers(headers)
                self.response_record.set_type("revisit")

                # grab up to the first \r\n\r\n (header block)
                header_content = b""
                while True:
                    line = self.response_file.readline(CHUNK_SIZE)
                    header_content += line
                    if not line or line == b"\r\n":
                        break

                self.response_record.set_content(header_content)
                print("\n\nwriting records\n\n")
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

        print(f"returning {event}")
        return event

    @override
    def close(self) -> None:
        self.conn.send(h11.ConnectionClosed())

        while not isinstance(self.next_event(CHUNK_SIZE), h11.PAUSED):
            # if the connection needs to close before a response is fully read, this reads the whole thing in so WARC
            # records can be written
            pass

        self.sock.close()