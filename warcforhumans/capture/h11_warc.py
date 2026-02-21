import http.client
import socket
import ssl
import urllib
from typing import Union, List, Tuple
from urllib.parse import urlsplit

import h11
import urllib3
from h11._headers import Headers
from requests import PreparedRequest, Response, Request
from requests.adapters import BaseAdapter
from requests.cookies import extract_cookies_to_jar, MockResponse, MockRequest
from requests.structures import CaseInsensitiveDict
from requests.utils import get_encoding_from_headers

class WrappedResponse(h11.Response):
    __slots__ = ("conn", "is_closed")

    def __init__(self, response: h11.Response = None, *,
                 headers: Union[Headers, List[Tuple[bytes, bytes]], List[Tuple[str, str]]] = None, status_code: int = None):
        if response:
            # Initialize from an existing h11.Response object
            super().__init__(headers=response.headers, status_code=response.status_code)
        else:
            # Initialize with provided headers and status_code
            super().__init__(headers=headers, status_code=status_code)

        self.conn = None
        self.is_closed = False

    def read(self, chunk_size):
        if self.is_closed:
            return

        event = self.conn.next_event(chunk_size)

        if isinstance(event, h11.Data):
            return event.data

        if isinstance(event, h11.EndOfMessage):
            return b""

        pass

    def set_connection(self, conn):
        self.conn = conn

class H11Connection:
    def __init__(self, hostname, port, secure):
        self.sock = socket.create_connection((hostname, port))
        if secure:
            self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=hostname)

        self.conn = h11.Connection(our_role=h11.CLIENT)

    def send_event(self, event: h11.Event):
        self.sock.sendall(self.conn.send(event))

    def next_event(self, chunk_size) -> h11.Event:
        while True:
            event = self.conn.next_event()
            if event is h11.NEED_DATA:
                bytes_received = self.sock.recv(chunk_size)
                self.conn.receive_data(bytes_received)
                print(f"{bytes_received!r}")
                continue

            return event

def _requests_headers_to_h11_headers(requests_headers: CaseInsensitiveDict[str]) -> list[tuple[str, str]]:
    h11_headers : list[tuple[str, str]] = []
    for key, value in requests_headers.items():
        h11_headers.append((key, value))
    return h11_headers


class H11Adapter(BaseAdapter):
    """
    A Requests adapter that uses the h11 library under the hood.
    """
    __attrs__ = [
        "pool"
    ]

    def __init__(self):
        super().__init__()

    def build_response(self, request: PreparedRequest, resp: h11.Response):
        response = Response()
        response.status_code = resp.status_code
        response.headers = CaseInsensitiveDict(
            (header.decode("iso-8859-1"), value.decode("iso-8859-1")) for header, value in resp.headers
        )

        response.encoding = get_encoding_from_headers(response.headers)
        response.raw = resp
        response.reason = http.client.responses[response.status_code]
        response.url = request.url
        urllib3_formatted_headers = urllib3.HTTPHeaderDict()
        for header, value in resp.headers:
            urllib3_formatted_headers.add(header.decode("iso-8859-1"), value.decode("iso-8859-1"))
        response.cookies.extract_cookies(MockResponse(urllib3_formatted_headers), MockRequest(request))
        response.request = request
        response.connection = self

        return response


    def send(
        self, request: PreparedRequest, stream: bool = False, timeout: float | tuple = None, verify: bool | str = True, cert=None, proxies=None
    ):
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

        parsed_url = urlsplit(request.url)
        hostname = parsed_url.hostname.split(":")[0]
        if ":" in parsed_url.hostname:
            port = int(parsed_url.hostname.split(":")[1])
        else:
            port = 80 if parsed_url.scheme == "http" else 443

        target = parsed_url.path
        if parsed_url.query:
            target += "?" + parsed_url.query


        headers = list(request.headers.items())
        headers.insert(0, ("Host", hostname))

        r = h11.Request(method=request.method,
                        headers=headers,
                        target=target)

        conn = H11Connection(hostname, port, parsed_url.scheme == "https")
        conn.send_event(r)
        conn.send_event(h11.EndOfMessage())

        resp = conn.next_event(1048)
        resp = WrappedResponse(resp)
        resp.set_connection(conn)



        return self.build_response(request, resp)

    def close(self):
        """Cleans up adapter specific items."""
        raise NotImplementedError


