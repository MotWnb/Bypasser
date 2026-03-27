import aiohttp
from urllib.parse import urlparse
from aiohttp.abc import AbstractResolver
import socket


class StaticResolver(AbstractResolver):
    def __init__(self, host, ip):
        self.host = host
        self.ip = ip
        self.default = aiohttp.resolver.DefaultResolver()

    async def resolve(self, host, port=0, family=0):
        if host == self.host:
            return [{
                "hostname": host,
                "host": self.ip,
                "port": port,
                "family": socket.AF_INET,
                "proto": 0,
                "flags": 0,
            }]
        return await self.default.resolve(host, port, family)

    async def close(self):
        await self.default.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        pass


async def fetch_with_forced_ip(url, ip):
    host = urlparse(url).hostname
    resolver = StaticResolver(host, ip)

    conn = aiohttp.TCPConnector(
        resolver=resolver,
        ssl=True,
        use_dns_cache=False
    )

    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.get(url, headers={"Host": host}) as resp:
            return await resp.text()
