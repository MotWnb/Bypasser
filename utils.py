import asyncio
import ssl
import socket
from urllib.parse import urlparse, urlunparse

import aiohttp
from aiohttp.abc import AbstractResolver


class StaticResolver(AbstractResolver):
    def __init__(self, target_host: str, target_ip: str):
        self.target_host = target_host
        self.target_ip = target_ip
        self._default = aiohttp.resolver.DefaultResolver()

    async def resolve(self, host, port=0, family=0):
        if host == self.target_host:
            return [{
                "hostname": host,
                "host": self.target_ip,
                "port": port,
                "family": socket.AF_INET,
                "proto": 0,
                "flags": 0,
            }]
        return await self._default.resolve(host, port, family)

    async def close(self):
        await self._default.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()


async def fetch_with_sni_and_original_host(url: str, ip: str, sni: str, timeout: float = 10.0) -> str:
    parsed = urlparse(url)
    original_host = parsed.hostname
    original_port = parsed.port

    netloc = sni if original_port is None else f"{sni}:{original_port}"
    request_url = urlunparse((parsed.scheme, netloc, parsed.path or "/", parsed.params, parsed.query, parsed.fragment))

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = True
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED

    resolver = StaticResolver(sni, ip)

    connector = aiohttp.TCPConnector(
        resolver=resolver,
        ssl=ssl_ctx,
        use_dns_cache=False,
    )

    timeout_obj = aiohttp.ClientTimeout(total=timeout)

    try:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj) as session:
            headers = {"Host": original_host}
            async with session.get(request_url, headers=headers) as resp:
                print("HTTP status:", resp.status)
                print("Response headers:", dict(resp.headers))
                print("Requested URL:", request_url)
                print("Sent Host header:", headers["Host"])
                resp.raise_for_status()
                return await resp.text()
    finally:
        await resolver.close()


if __name__ == "__main__":
    async def main():
        url = "https://steamcommunity.com/"
        ip = "23.59.200.146"
        sni = "www.valvesoftware.com"
        try:
            text = await fetch_with_sni_and_original_host(url, ip, sni, timeout=5)
            print(text)
        except Exception as e:
            print("Failed:", type(e).__name__, e)

    asyncio.run(main())
