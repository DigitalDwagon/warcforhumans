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
from urllib3 import HTTPResponse


class BodyStreamFromH11Response:
    __slots__ = ("conn", "closed")

    def __init__(self, conn):

        self.conn = conn
        self.closed = False

    def read(self, chunk_size):
        if self.closed:
            return

        event = self.conn.next_event(chunk_size)

        if isinstance(event, h11.Data):
            return event.data

        if isinstance(event, h11.EndOfMessage):
            self.closed = True
            return b""

        pass

    def close(self):
        self.closed = True


class H11Connection:
    def __init__(self, hostname, port, secure):
        self.closed = False
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


    def send(self, request: PreparedRequest, stream: bool = False, timeout: float | tuple = None, verify: bool | str = True, cert=None, proxies=None):
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

        r = h11.Request(method=request.method,
                        headers=headers,
                        target=target)

        conn = H11Connection(hostname, port, scheme == "https")
        conn.send_event(r)
        conn.send_event(h11.EndOfMessage())

        resp = conn.next_event(1048)

        return self.build_response(request, resp, conn)

    def close(self):
        """Cleans up adapter specific items."""
        raise NotImplementedError


