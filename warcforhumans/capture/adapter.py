import http.client
from typing import override
from urllib.parse import urlsplit

import h11
import urllib3
from requests import PreparedRequest, Response
from requests.adapters import BaseAdapter
from requests.cookies import extract_cookies_to_jar
from requests.structures import CaseInsensitiveDict
from requests.utils import get_encoding_from_headers
from urllib3 import HTTPResponse

from warcforhumans.api import WARCWriter
from warcforhumans.capture.connection import ConnectionInfo, H11Connection, WARCWritingH11Connection

CHUNK_SIZE = 2048

class BodyStreamFromH11Response:
    __slots__ = ["conn", "closed"]

    def __init__(self, conn: H11Connection):

        self.conn: H11Connection = conn
        self.closed: bool = False

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
            to a CA bundle to use.
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
        info = ConnectionInfo(scheme, hostname, port, connect_timeout, read_timeout, verify, cert, proxies)
        conn = WARCWritingH11Connection(info, WARC_WRITER)


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

        resp = conn.next_event(CHUNK_SIZE)

        return self.build_response(request, resp, conn)

    def close(self):
        """Cleans up adapter specific items."""
        raise NotImplementedError


