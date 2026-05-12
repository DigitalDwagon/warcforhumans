from typing import override

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3 import HTTPConnectionPool, HTTPSConnectionPool

from warcforhumans.capture.httpconnection import HTTPConnection, HTTPSConnection


class H11HTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = HTTPConnection
    warc_writer = None

    def _new_conn(self):
        """Create a new connection and set warc_writer if available"""
        conn = super()._new_conn()
        if self.warc_writer is not None:
            conn.warc_writer = self.warc_writer
        return conn


class H11HTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = HTTPSConnection
    warc_writer = None

    def _new_conn(self):
        """Create a new connection and set warc_writer if available"""
        conn = super()._new_conn()
        if self.warc_writer is not None:
            conn.warc_writer = self.warc_writer
        return conn


class H11HTTPPoolManager(urllib3.PoolManager):
    def __init__(self, num_pools=10, headers=None, **pool_kwargs):
        # Extract warc_writer from pool_kwargs if present, don't pass to parent
        warc_writer = pool_kwargs.pop('warc_writer', None)
        super().__init__(num_pools=num_pools, headers=headers, **pool_kwargs)
        self.pool_classes_by_scheme = {"http": H11HTTPConnectionPool, "https": H11HTTPSConnectionPool}
        self.warc_writer = warc_writer

    def connection_from_host(self, host, port=None, scheme="http", pool_kwargs=None):
        """Get a connection pool for the given host, setting warc_writer if available"""
        pool = super().connection_from_host(host, port=port, scheme=scheme, pool_kwargs=pool_kwargs)
        if self.warc_writer is not None:
            pool.warc_writer = self.warc_writer
        return pool


class WARCHTTPAdapter(HTTPAdapter):
    def __init__(self, warc_writer=None, *args, **kwargs):
        self.warc_writer = warc_writer
        super().__init__(*args, **kwargs)

    @override
    def init_poolmanager(
            self, connections, maxsize, block=requests.adapters.DEFAULT_POOLBLOCK, **pool_kwargs
    ):
        """Initializes a urllib3 PoolManager.

        This method should not be called from user code, and is only
        exposed for use when subclassing the
        :class:`HTTPAdapter <requests.adapters.HTTPAdapter>`.

        :param connections: The number of urllib3 connection pools to cache.
        :param maxsize: The maximum number of connections to save in the pool.
        :param block: Block when no free connections are available.
        :param pool_kwargs: Extra keyword arguments used to initialize the Pool Manager.
        """
        # save these values for pickling
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block

        self.poolmanager = H11HTTPPoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            warc_writer=self.warc_writer,
            **pool_kwargs,
        )