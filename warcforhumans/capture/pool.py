import queue
import typing
from _thread import LockType
from threading import Lock
import weakref

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
        if self.closed:
            raise RuntimeError("Pool is closed, cannot get a connection.")

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
        if self.closed:
            conn.close()
            return

        if not conn.closed:
            if not self.available_connections.full():
                conn_ref = weakref.ref(conn)
                _ = weakref.finalize(conn_ref, conn.close)
                self.available_connections.put(conn_ref)
        else:
            if self.available_connections.empty():
                self.available_connections.put(None)

    def close(self) -> None:
        # TODO this should close all available connections in the pool.
        self.closed = True


class PoolManager:
    def __init__(self, num_pools: int = 10, **pool_kw: dict[str, typing.Any] | None) -> None:
        self.num_pools: int = num_pools
        self.pools: dict[ConnectionInfo, H11ConnectionPool] = {}
        self.pool_kw : dict[str, typing.Any] = dict(pool_kw)

    def close(self) -> None:
        for info, pool in self.pools.items():
            pool.close()

    def connection_from_info(self, info: ConnectionInfo) -> H11Connection:
        return self.pool_from_info(info).get()

    def connection_from_host(self, scheme: str, host: str, port: int) -> H11Connection:
        info = ConnectionInfo(scheme, host, port)
        return self.connection_from_info(info)

    def pool_from_info(self, info: ConnectionInfo, **pool_kw: typing.Any)-> H11ConnectionPool:
        pool = self.pools.get(info)
        if pool is not None:
            return pool

        if not pool_kw:
            pool_kw = self.pool_kw

        pool = H11ConnectionPool(info, **pool_kw)
        self.pools[info] = pool
        return pool