import queue
from ssl import cert_time_to_seconds
import typing
from _thread import LockType
from collections import deque
from threading import Lock

from warcforhumans.capture.h11_warc import H11Connection


class PoolKey(typing.NamedTuple):
    scheme: str
    host: str
    port: int
    verify: int | str | None
    cert: any



class H11ConnectionPool:
    """
    A connection pool that manages persistent H11 connections.
    Reuses connections across multiple requests to the same host.
    """

    def __init__(self,
                 hostname: str,
                 port: int,
                 secure: bool,
                 maxsize: int = 1,
                 connect_timeout: float | None = None,
                 read_timeout: float | None = None,
                 block: bool = False,
                 verify: bool | str | None = None,
                 cert=None,
                 proxies=None) -> None:

        if proxies:
            raise NotImplementedError("Proxies are not yet supported by H11ConnectionPool")

        self.hostname: str = hostname
        self.port: int = port
        self.maxsize: int = maxsize
        self.connect_timeout : float | None = connect_timeout
        self.read_timeout: float | None = read_timeout
        self.block: bool = block
        self.secure: bool = secure
        self.verify: bool | str | None = verify
        self.cert = None


        self.closed: bool = False
        self.available_connections: queue.LifoQueue[H11Connection | None] = queue.LifoQueue(maxsize=maxsize)
        self.busy_connections: list[H11Connection] = []

        self._lock: LockType = Lock()

    def _create_connection(self) -> H11Connection:
        return H11Connection(self.hostname, self.port, self.secure, self.connect_timeout, self.read_timeout,
                             self.verify, self.cert)


    def get(self) -> H11Connection:
        if len(self.busy_connections) < self.maxsize and self.available_connections.empty():
            self.available_connections.put(None)

        try:
            if self.block:
                conn = self.available_connections.get()
            else:
                conn = self.available_connections.get_nowait()

            if not conn:
                conn = self._create_connection()

            self.busy_connections.append(conn)
            return conn
        except queue.Empty:
            # Creates a throwaway connection that won't be released.
            return self._create_connection()

    def release(self, conn: H11Connection) -> None:
        self.busy_connections.remove(conn)
        if not conn.closed:
            if not self.available_connections.full():
                self.available_connections.put(conn)
        else:
            if self.available_connections.empty():
                self.available_connections.put(None)
