import http.client
from email.message import Message
from http.client import ResponseNotReady
from importlib.metadata import version
import os
import ssl
from typing_extensions import TYPE_CHECKING, override

import h11
from urllib3 import HTTPResponse
import urllib3.connection
from urllib3.exceptions import ResponseError
import urllib3.util
import typing
import socket

from urllib3._base_connection import ProxyConfig, _TYPE_BODY, _ResponseOptions

from warcforhumans.api import WARCWriter

if TYPE_CHECKING:
    from urllib3._base_connection import BaseHTTPConnection as _BaseHTTPConnection
    from urllib3._base_connection import BaseHTTPSConnection as _BaseHTTPSConnection
else:
    _BaseHTTPConnection = object
    _BaseHTTPSConnection = object

from urllib3.util import Url
from urllib3.util.connection import _TYPE_SOCKET_OPTIONS
from urllib3.util.timeout import _TYPE_TIMEOUT, _DEFAULT_TIMEOUT, Timeout

import warcforhumans.capture.util as util
from warcforhumans.capture.connection import ConnectionInfo, H11Connection, SecureConnectionOptions, \
    WARCWritingH11Connection

DEFAULT_USER_AGENT: str = f"warcforhumans/{version("warcforhumans")} (like urllib3/{version("urllib3")}"
CHUNK_SIZE = 2048


class BodyStreamFromH11Response(typing.IO[bytes]):
    # todo: implement all IO[bytes] methods
    def __init__(self, conn: H11Connection):

        self.conn: H11Connection = conn
        self._closed = False

    @override
    def read(self, chunk_size: int = CHUNK_SIZE):
        if self.closed:
            return b""

        event = self.conn.next_event(chunk_size)

        if isinstance(event, h11.Data):
            return event.data

        if isinstance(event, h11.EndOfMessage):
            self.closed = True
            return b""

        raise RuntimeError("Wrong event type!") # todo: better error type

    @override
    def close(self):
        self.closed = True

    @property
    @override
    def closed(self) -> bool:
        return self._closed

    @closed.setter
    def closed(self, value: bool):
        self._closed = value


class HTTPConnection(_BaseHTTPConnection):
    scheme: typing.ClassVar[str] = "http"
    default_port: typing.ClassVar[int] = 80

    default_socket_options: typing.ClassVar[_TYPE_SOCKET_OPTIONS] = [
        (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    ]
    ConnectionCls: type[H11Connection] = H11Connection

    proxy: Url | None = None
    proxy_config: ProxyConfig | None = None
    proxy_is_verified: bool | None

    is_verified: bool = False

    def __init__(  # pyright: ignore[reportMissingSuperCall]
            self,
            host: str,
            port: int | None = None,
            *,
            timeout: _TYPE_TIMEOUT = _DEFAULT_TIMEOUT,
            source_address: tuple[str, int] | None = None,
            blocksize: int = 16384,
            socket_options: _TYPE_SOCKET_OPTIONS | None = default_socket_options,
            proxy: Url | None = None,
            proxy_config: ProxyConfig | None = None,
            warc_writer: WARCWriter | None = None
    ) -> None:
        if proxy is not None or proxy_config is not None:
            raise NotImplementedError("warcforhumans HTTPConnection does not support proxies. Sorry!")

        print("init")

        if port is not None:
            self.port: int = port
        else:
            self.port = self.default_port

        #self._validate_host()
        self.warc_writer: WARCWriter | None = warc_writer
        self.host: str = host
        self.timeout: float | None = Timeout.resolve_default_timeout(timeout)
        self.source_address: tuple[str, int] | None = source_address
        self.blocksize: int = blocksize
        self.socket_options: _TYPE_SOCKET_OPTIONS | None = socket_options
        self.sock: socket.socket | None = None
        self.conn: H11Connection | None = None
        self.secure_connection_options: SecureConnectionOptions | None = None


    def _new_conn(self) -> H11Connection:
        if self.socket_options is None:
            self.socket_options = []

        #return self.ConnectionCls(ConnectionInfo(self.scheme, self.host, self.port, socket_options=self.socket_options), secure_options=self.secure_connection_options)
        conn = WARCWritingH11Connection(ConnectionInfo(self.scheme, self.host, self.port, socket_options=self.socket_options), self.warc_writer, secure_options=self.secure_connection_options)
        self.is_verified = conn.is_verified
        print(f"conn reports as verified: {conn.is_verified}")
        return conn

    @typing.override
    def connect(self) -> None:
        print("asked to connect")

        if self.conn is None:
            self.conn = self._new_conn()
            return

        if self.conn.closed:
            self.conn = self._new_conn()
            return

        self.conn.start_next_cycle()


    @typing.override
    def set_tunnel(
        self,
        host: str,
        port: int | None = None,
        headers: typing.Mapping[str, str] | None = None,
        scheme: str = "http",
    ) -> None:
        raise NotImplementedError("warcforhumans HTTPConnection does not support proxies. Sorry!")


    @typing.override
    def close(self) -> None:
        self.conn.close()
        self.conn = None

    @property
    @typing.override
    def is_closed(self) -> bool:
        # Todo
        return self.conn is None

    @property
    @typing.override
    def is_connected(self) -> bool:
        """Whether the connection is actively connected to any origin (proxy or target)"""
        return self.conn is not None

    @property
    @typing.override
    def has_connected_to_proxy(self) -> bool:
        """Whether the connection has successfully connected to its proxy.
        This returns False if no proxy is in use. Used to determine whether
        errors are coming from the proxy layer or from tunnelling to the target origin.
        """
        return False

    @typing.override
    def request(self,
                method: str,
                url: str,
                body: _TYPE_BODY | None = None,
                headers: typing.Mapping[str, str] | None = None,
                *,
                chunked: bool = False,
                preload_content: bool = True,
                decode_content: bool = True,
                enforce_content_length: bool = True
                ) -> None:
        self._response_options = _ResponseOptions(
            request_method=method,
            request_url=url,
            preload_content=preload_content,
            decode_content=decode_content,
            enforce_content_length=enforce_content_length,
        )

        print(f"method: {method}\nurl: {url}\nheaders:{headers}")

        if self.conn is None or self.conn.conn.states[h11.CLIENT] is not h11.IDLE:
            self.connect()
            if self.conn is None:
                raise RuntimeError("Could not create a new connection") # todo better error type

        if headers is None:
            headers = {}

        h11_headers = list(headers.items())
        if headers.get("Host") is None:
            h11_headers.insert(0, ("Host", util.normalize_netloc(self.host, scheme=self.scheme, port=self.port)))
        if headers.get("Accept-Encoding") is None:
            h11_headers.append(("Accept-Encoding", "identity"))

        chunks_and_cl = urllib3.util.request.body_to_chunks(body, method=method, blocksize=self.blocksize)
        chunks = chunks_and_cl.chunks
        content_length = chunks_and_cl.content_length

        if not chunked and content_length is None and chunks is not None:
            chunked = True

        if chunked and headers.get("Transfer-Encoding") is None:
            h11_headers.append(("Transfer-Encoding", "chunked"))

        if not chunked and content_length is not None and headers.get("Content-Length") is None:
            h11_headers.append(("Content-Length", str(content_length)))

        if headers.get("User-Agent") is None:
            h11_headers.append(("User-Agent", DEFAULT_USER_AGENT)) # todo this is not robust enough

        request = h11.Request(method=method, headers=h11_headers, target=url)
        self.conn.send_event(request)

        if chunks:
            for chunk in chunks:
                self.conn.send_event(h11.Data(data=chunk))
        self.conn.send_event(h11.EndOfMessage())

    @typing.override
    def getresponse(self) -> HTTPResponse:
        if self.conn is None:
            print("Connection or sock is none")
            print(f"conn: {self.conn}\nsock: {self.sock}")
            raise ResponseNotReady()

        if self.conn.conn.our_state is not h11.DONE:
            print("request not finished")
            raise ResponseNotReady()

        if self._response_options is None:
            print("response options is none")
            raise ResponseNotReady()

        resp_options = self._response_options
        self._response_options = None

        self.conn.sock.settimeout(self.timeout)

        r = self.conn.next_event(self.blocksize)
        if not isinstance(r, h11.Response):
            raise ResponseError()
        print(r)

        urllib3_formatted_headers = urllib3.HTTPHeaderDict()
        for header, value in r.headers:
            urllib3_formatted_headers.add(header.decode("iso-8859-1"), value.decode("iso-8859-1"))

        version_number = 0
        if r.http_version == b"1.1":
            version_number = 11
        if r.http_version == b"1.0":
            version_number = 10

        response = HTTPResponse(
            body=BodyStreamFromH11Response(self.conn),
            headers=urllib3_formatted_headers,
            status=r.status_code,
            version=version_number,
            version_string="HTTP/"+r.http_version.decode(),
            reason=http.client.responses[r.status_code],
            preload_content=resp_options.preload_content,
            decode_content=resp_options.decode_content,
            enforce_content_length=resp_options.enforce_content_length,
            request_method=resp_options.request_method,
            request_url=resp_options.request_url
        )
        return response

class HTTPSConnection(HTTPConnection, _BaseHTTPSConnection):  # pyright: ignore[reportUnsafeMultipleInheritance]
    scheme: typing.ClassVar[str] = "https"
    default_port: typing.ClassVar[int] = 443
    proxy_is_verified = False # Proxies are not supported so they are never verified

    def __init__(  # pyright: ignore[reportMissingSuperCall]
            self,
            host: str,
            port: int | None = None,
            *,
            timeout: _TYPE_TIMEOUT = _DEFAULT_TIMEOUT,
            source_address: tuple[str, int] | None = None,
            blocksize: int = 16384,
            socket_options: _TYPE_SOCKET_OPTIONS | None = None, # todo check
            proxy: Url | None = None,
            proxy_config: ProxyConfig | None = None,
            cert_reqs: int | str | None = None,
            assert_hostname: None | str | typing.Literal[False] = None,
            assert_fingerprint: str | None = None,
            server_hostname: str | None = None,
            ssl_context: ssl.SSLContext | None = None,
            ca_certs: str | None = None,
            ca_cert_dir: str | None = None,
            ca_cert_data: None | str | bytes = None,
            ssl_minimum_version: int | None = None,
            ssl_maximum_version: int | None = None,
            ssl_version: int | str | None = None,  # Deprecated
            cert_file: str | None = None,
            key_file: str | None = None,
            key_password: str | None = None,
            warc_writer: WARCWriter | None = None
    ) -> None:
        super().__init__(
            host,
            port=port,
            timeout=timeout,
            source_address=source_address,
            blocksize=blocksize,
            socket_options=socket_options,
            proxy=proxy,
            proxy_config=proxy_config,
            warc_writer=warc_writer
        )
        self.cert_reqs: int | str | None = cert_reqs
        self.assert_hostname: None | str | typing.Literal[False] = assert_hostname
        self.assert_fingerprint: str | None = assert_fingerprint
        self.server_hostname: str | None = server_hostname
        self.ssl_context: ssl.SSLContext | None = ssl_context
        self.ca_certs: str | None = ca_certs and os.path.expanduser(ca_certs)
        self.ca_cert_dir: str | None = ca_cert_dir and os.path.expanduser(ca_cert_dir)
        self.ca_cert_data: None | str | bytes = ca_cert_data
        self.ssl_minimum_version: int | None = ssl_minimum_version
        self.ssl_maximum_version: int | None = ssl_maximum_version
        self.ssl_version: int | str | None = ssl_version # Deprecated
        self.cert_file: str | None = cert_file
        self.key_file: str | None = key_file
        self.key_password: str | None = key_password
        if cert_reqs is None:
            if self.ssl_context is not None:
                self.cert_reqs = self.ssl_context.verify_mode
            else:
                self.cert_reqs = ssl.CERT_REQUIRED

        self.secure_connection_options: SecureConnectionOptions | None = SecureConnectionOptions(
            cert_reqs=self.cert_reqs,
            assert_hostname=assert_hostname,
            assert_fingerprint=assert_fingerprint,
            server_hostname=server_hostname,
            ssl_context=ssl_context,
            ca_certs=ca_certs,
            ca_cert_dir=ca_cert_dir,
            ca_cert_data=ca_cert_data,
            ssl_minimum_version=ssl_minimum_version,
            ssl_maximum_version=ssl_maximum_version,
            ssl_version=ssl_version,
            cert_file=cert_file,
            key_file=key_file,
            key_password=key_password
        )



    def set_cert(
        self,
        key_file: str | None = None,
        cert_file: str | None = None,
        cert_reqs: int | str | None = None,
        key_password: str | None = None,
        ca_certs: str | None = None,
        assert_hostname: None | str | typing.Literal[False] = None,
        assert_fingerprint: str | None = None,
        ca_cert_dir: str | None = None,
        ca_cert_data: None | str | bytes = None,
    ) -> None:
        """
        DEPRECATED
        This method should only be called once, before the connection is used.
        """


        # If cert_reqs is not provided we'll assume CERT_REQUIRED unless we also
        # have an SSLContext object in which case we'll use its verify_mode.
        if cert_reqs is None:
            if self.ssl_context is not None:
                cert_reqs = self.ssl_context.verify_mode
            else:
                cert_reqs = ssl.CERT_REQUIRED

        self.key_file = key_file
        self.cert_file = cert_file
        self.cert_reqs = cert_reqs
        self.key_password = key_password
        self.assert_hostname = assert_hostname
        self.assert_fingerprint = assert_fingerprint
        self.ca_certs = ca_certs and os.path.expanduser(ca_certs)
        self.ca_cert_dir = ca_cert_dir and os.path.expanduser(ca_cert_dir)
        self.ca_cert_data = ca_cert_data