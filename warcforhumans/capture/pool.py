import queue
import typing
from _thread import LockType
from threading import Lock
import weakref

from urllib3 import Timeout

from warcforhumans.capture.connection import H11Connection, ConnectionInfo


class H11ConnectionPool:
    """
    A connection pool that manages persistent H11 connections.
    Reuses connections across multiple requests to the same host.
    """

    def __init__(self,
                 info: ConnectionInfo,
                 maxsize: int = 1,
                 block: bool = False) -> None:

        if info.proxies is not None:
            raise NotImplementedError("Proxies are not yet supported by H11ConnectionPool")

        self.info: ConnectionInfo = info
        self.maxsize: int = maxsize
        self.block: bool = block


        self.closed: bool = False
        self.available_connections: queue.LifoQueue[weakref.ref[H11Connection] | None] = queue.LifoQueue(maxsize=maxsize)
        self.busy_connections: list[H11Connection] = []

        self._lock: LockType = Lock()

    def _create_connection(self, throwaway: bool = False) -> H11Connection:
        return H11Connection(self.info, throwaway)


    def get(self) -> H11Connection:
        if len(self.busy_connections) < self.maxsize and self.available_connections.empty():
            self.available_connections.put(None)

        try:
            if self.block:
                conn = self.available_connections.get()
            else:
                conn = self.available_connections.get_nowait()

            if isinstance(conn, weakref.ref):
                conn = conn()

            if not conn:
                conn = self._create_connection()

            self.busy_connections.append(conn)
            return conn
        except queue.Empty:
            # Creates a throwaway connection that won't be released and will close itself after finishing
            return self._create_connection(True)

    def release(self, conn: H11Connection) -> None:
        self.busy_connections.remove(conn)
        if not conn.closed:
            if not self.available_connections.full():
                conn_ref = weakref.ref(conn)
                _ = weakref.finalize(conn_ref, conn.close)
                self.available_connections.put(conn_ref)
        else:
            if self.available_connections.empty():
                self.available_connections.put(None)
