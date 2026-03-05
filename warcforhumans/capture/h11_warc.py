import http.client
import socket
import ssl
import hashlib
import time
from io import BufferedRandom
import tempfile
from typing import override
from urllib.parse import urlsplit

import h11
import urllib3
from _hashlib import HASH
from requests import PreparedRequest, Response
from requests.adapters import BaseAdapter
from requests.cookies import extract_cookies_to_jar
from requests.structures import CaseInsensitiveDict
from requests.utils import get_encoding_from_headers
from urllib3 import HTTPResponse, request

import warcforhumans.api
from warcforhumans.api import WARCRecord, WARCWriter

CHUNK_SIZE = 2048

class BodyStreamFromH11Response:
    __slots__ = ["conn", "closed"]

    def __init__(self, conn):

        self.conn = conn
        self.closed = False

    def read(self, chunk_size: int = CHUNK_SIZE):
        if self.closed:
            return b""

        event = self.conn.next_event(chunk_size)

        if isinstance(event, h11.Data):
            return event.data

        if isinstance(event, h11.EndOfMessage):
            self.closed = True
            return b""

        pass

    def close(self):
        self.closed = True

WARC_WRITER: WARCWriter = WARCWriter("h11example-$date-$number-$serial",
                             #compressor=GZIPCompressor(),
                             warcinfo_fields={"operator": "some person"},
                             software="example-script/0.1"
                             )

class H11Connection:
    def __init__(self,
                 hostname : str,
                 port : int,
                 secure : bool,
                 connect_timeout : float | None = None,
                 read_timeout : float | None = None,
                 verify: bool | str | None = None,
                 cert = None,
                 proxies = None
                 ) -> None:
        self.hostname: str = hostname
        self.port: int = port
        self.secure: bool = secure
        self.read_timeout: float | None = read_timeout
        self.verify: bool | str | None = verify

        self.closed: bool = False

        self.sock = socket.create_connection((hostname, port), timeout=connect_timeout)
        self.sock.settimeout(read_timeout)
        if secure:
            if isinstance(verify, str):
                # todo custom paths not working
                ctx = ssl.create_default_context(capath=verify)
            elif isinstance(verify, bool) and verify:
                ctx = ssl.create_default_context()
                ctx.verify_mode = ssl.CERT_REQUIRED
            else:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            if cert:
                # todo not working
                if isinstance(cert, tuple) and len(cert) == 2:
                    ctx.load_cert_chain(certfile=cert[0], keyfile=cert[1])
                elif isinstance(cert, str):
                    ctx.load_cert_chain(certfile=cert)
                else:
                    raise ValueError(
                        "Invalid certificate format. Provide a path to the certificate or a tuple (certfile, keyfile).")

            self.sock = ctx.wrap_socket(self.sock, server_hostname=hostname)

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
                self.sock.close()
                self.closed = True

            return event

    def close(self) -> None:
        self.conn.send(h11.ConnectionClosed())
        self.sock.close()

    def start_next_cycle(self) -> None:
        self.conn.start_next_cycle()

class WARCWritingH11Connection(H11Connection):
    def __init__(self,
                 hostname: str,
                 port: int,
                 secure: bool,
                 warc_writer: WARCWriter,
                 connect_timeout: float | None = None,
                 read_timeout: float | None = None,
                 verify: bool | str | None = None,
                 cert=None,
                 proxies=None,

                 ):
        super().__init__(hostname, port, secure, connect_timeout, read_timeout, verify, cert, proxies)

        self.request_record: WARCRecord | None = None
        self.response_record: WARCRecord | None = None
        self.response_payload_hash: HASH | None = None
        self.response_file: BufferedRandom | None = None
        self.warc_writer: WARCWriter = warc_writer


    @override
    def send_event(self, event: h11.Event) -> None:
        if isinstance(event, h11.Request):
            # todo check if there's another wip record
            url = ""
            if self.secure:
                url += "https"
            else:
                url += "http"

            url +=  "://" + self.hostname

            if self.secure and self.port != 443:
                url += ":" + str(self.port)
            elif not self.secure and self.port != 80:
                url += ":" + str(self.port)

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
            self.response_record.set_header(WARCRecord.WARC_PAYLOAD_DIGEST, warcforhumans.api.hash_to_string(self.response_payload_hash))

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

            print(f"returning {event}")
            return event

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



class H11Adapter(BaseAdapter):
    """
    A Requests adapter that uses the h11 library under the hood.
    """
    __attrs__ = [
        "pool"
    ]

    def __init__(self):
        super().__init__()

    def _parse_timeout(self, timeout) -> tuple:
        """
        Parses a timeout into a consistent (connect timeout, read timeout) format.
        :param timeout: How long to wait for the server to send
            data before giving up, as a float, or a :ref:`(connect timeout,
            read timeout) <timeouts>` tuple.
        :return: (connect timeout, read timeout). One or both of these values may be None.
        """
        if isinstance(timeout, tuple):
            return timeout

        if timeout is not None:
            return timeout, timeout

        return None, None

    def _parse_url(self, url: str) -> tuple[str, str, int, str]:
        """
        Parses a raw URL.
        :param url: The URL to parse
        :return: A tuple (scheme, hostname, port, target) from the URL.
        """
        parsed_url = urlsplit(url, allow_fragments=False)
        hostname = parsed_url.hostname.split(":")[0]
        if ":" in parsed_url.hostname:
            port = int(parsed_url.hostname.split(":")[1])
        else:
            port = 80 if parsed_url.scheme == "http" else 443

        target = parsed_url.path
        if parsed_url.query:
            target += "?" + parsed_url.query

        return parsed_url.scheme, hostname, port, target

    def build_response(self, request: PreparedRequest, resp: h11.Response, conn: H11Connection):
        urllib3_formatted_headers = urllib3.HTTPHeaderDict()
        for header, value in resp.headers:
            urllib3_formatted_headers.add(header.decode("iso-8859-1"), value.decode("iso-8859-1"))

        urllib3_response = HTTPResponse(
            body = BodyStreamFromH11Response(conn),
            headers=urllib3_formatted_headers,
            preload_content=False,
            decode_content=True
        )


        response = Response()
        response.status_code = resp.status_code
        response.headers = CaseInsensitiveDict(
            (header.decode("iso-8859-1"), value.decode("iso-8859-1")) for header, value in resp.headers
        )

        response.encoding = get_encoding_from_headers(response.headers)
        response.raw = urllib3_response
        response.reason = http.client.responses[response.status_code]
        response.url = request.url
        extract_cookies_to_jar(response.cookies, urllib3_response, request)

        response.request = request
        response.connection = self

        return response


    @override
    def send(self, request: PreparedRequest, stream: bool = False,
             timeout: float | tuple[float, float] | tuple[float, None] | None = None,
             verify: bool | str = True, cert=None, proxies=None):
        """Sends PreparedRequest object. Returns Response object.

        :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
        :param stream: (optional) Whether to stream the request content.
        :param timeout: (optional) How long to wait for the server to send
            data before giving up, as a float, or a :ref:`(connect timeout,
            read timeout) <timeouts>` tuple.
        :type timeout: float or tuple
        :param verify: (optional) Either a boolean, in which case it controls whether we verify
            the server's TLS certificate, or a string, in which case it must be a path
            to a CA bundle to use
        :param cert: (optional) Any user-provided SSL certificate to be trusted.
        :param proxies: (optional) The proxies dictionary to apply to the request.
        """

        scheme, hostname, port, target = self._parse_url(request.url)


        headers = list(request.headers.items())
        headers.insert(0, ("Host", hostname))


        chunked = not (request.body is None or "Content-Length" in request.headers)
        if chunked:
            headers.append(("Transfer-Encoding", "chunked"))

        print(headers)
        r = h11.Request(method=request.method,
                        headers=headers,
                        target=target)



        connect_timeout, read_timeout = self._parse_timeout(timeout)
        conn = WARCWritingH11Connection(hostname, port, scheme == "https", WARC_WRITER, connect_timeout=connect_timeout,
                             read_timeout=read_timeout, cert=cert, verify=verify, proxies=proxies)



        conn.send_event(r)
        if request.body and not hasattr(request.body, "read"):
            conn.send_event(h11.Data(request.body, chunked, chunked))
        if request.body and hasattr(request.body, "read"):
            while True:
                chunk = request.body.read(CHUNK_SIZE)
                if not chunk:
                    break
                conn.send_event(h11.Data(data=chunk))
            pass
        conn.send_event(h11.EndOfMessage())


        print("adapter getting events")
        resp = conn.next_event(CHUNK_SIZE)

        return self.build_response(request, resp, conn)

    def close(self):
        """Cleans up adapter specific items."""
        raise NotImplementedError


