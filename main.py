from loguru import logger
import asyncio
import time
import socket
import aiodns
import aiohttp

logger.add("doh.log", rotation="5 MB", retention="7 days", compression="zip", enqueue=True)

DOH_BACKENDS = [
    "https://223.5.5.5/dns-query",
    "https://223.6.6.6/dns-query",
    "https://sm2.doh.pub/dns-query",
    "https://101.101.101.101/dns-query",
    "https://dns.twnic.tw/dns-query",
    "https://1.1.1.1/dns-query",
    "https://1.0.0.1/dns-query",
    "https://1.1.1.3/dns-query",
    "https://1.0.0.3/dns-query",
    "https://8.8.8.8/dns-query",
    "https://8.8.4.4/dns-query",
    "https://v.recipes/dns-query",
    "https://185.222.222.222/dns-query",
    "https://45.11.45.11/dns-query",
    "https://de-dus.doh.sb/dns-query",
    "https://de-fra.doh.sb/dns-query",
    "https://nl-ams.doh.sb/dns-query",
    "https://uk-lon.doh.sb/dns-query",
    "https://ee-tll.doh.sb/dns-query",
    "https://jp-kix.doh.sb/dns-query",
    "https://jp-nrt.doh.sb/dns-query",
    "https://hk-hkg.doh.sb/dns-query",
    "https://au-syd.doh.sb/dns-query",
    "https://us-chi.doh.sb/dns-query",
    "https://us-nyc.doh.sb/dns-query",
    "https://us-sjc.doh.sb/dns-query",
    "https://in-blr.doh.sb/dns-query",
    "https://sg-sin.doh.sb/dns-query",
    "https://kr-sel.doh.sb/dns-query",
    "https://ru-mow.doh.sb/dns-query",
    "https://ca-yyz.doh.sb/dns-query",
    "https://de-ber.doh.sb/dns-query",
    "https://45.76.113.31/dns-query",
    "https://doh.seby.io/dns-query"
]

BACKEND_ALIAS = {
    "https://1.1.1.1/dns-query": "cloudflare doh",
    "https://1.0.0.1/dns-query": "cloudflare doh",
    "https://1.1.1.3/dns-query": "cloudflare family",
    "https://1.0.0.3/dns-query": "cloudflare family",
    "https://8.8.8.8/dns-query": "google doh",
    "https://8.8.4.4/dns-query": "google doh",
    "https://223.5.5.5/dns-query": "aliyun doh",
    "https://223.6.6.6/dns-query": "aliyun doh",
    "https://101.101.101.101/dns-query": "twnic quad101",
    "https://dns.twnic.tw/dns-query": "twnic quad101",
    "https://v.recipes/dns-query": "v.recipes",
    "https://185.222.222.222/dns-query": "dns.sb main",
    "https://45.11.45.11/dns-query": "dns.sb main"
}


def alias_of(url):
    if url in BACKEND_ALIAS:
        return BACKEND_ALIAS[url]
    if ".doh.sb" in url:
        host = url.split("//")[1].split("/")[0]
        return "dns.sb " + host.split(".")[0]
    return ""


CHECK_HOST = "steamcommunity.com"
CHECK_TYPE_A = b"\x00\x01"
AKAMAI_KEYWORD = "akamai"
CHECK_TIMEOUT = 3
REFRESH_INTERVAL = 60


class DohSelector:
    def __init__(self, backends):
        self.backends = backends
        self.current = None
        self.lock = asyncio.Lock()
        self.resolver = aiodns.DNSResolver()

    async def check_backend(self, session, url):
        tid = int(time.time() * 1000) & 0xFFFF
        header = tid.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        labels = CHECK_HOST.split(".")
        qname = b"".join(len(l).to_bytes(1, "big") + l.encode() for l in labels) + b"\x00"
        question = qname + CHECK_TYPE_A + b"\x00\x01"
        payload = header + question
        start = time.perf_counter()
        try:
            async with session.post(
                    url,
                    data=payload,
                    headers={
                        "content-type": "application/dns-message",
                        "accept": "application/dns-message",
                    },
                    timeout=CHECK_TIMEOUT,
            ) as r:
                if r.status != 200:
                    logger.warning(f"{url} status {r.status}")
                    return None
                data = await r.read()
        except Exception as e:
            logger.warning(f"{url} fail {e}")
            return None
        rtt = (time.perf_counter() - start) * 1000
        if len(data) < 12:
            return None
        ancount = int.from_bytes(data[6:8], "big")
        if ancount == 0:
            return None
        offset = 12
        while data[offset] != 0:
            offset += 1 + data[offset]
        offset += 1 + 4
        answers = []
        for _ in range(ancount):
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while data[offset] != 0:
                    offset += 1 + data[offset]
                offset += 1
            rtype = data[offset: offset + 2]
            offset += 8
            rdlength = int.from_bytes(data[offset: offset + 2], "big")
            offset += 2
            rdata = data[offset: offset + rdlength]
            offset += rdlength
            if rtype == CHECK_TYPE_A and rdlength == 4:
                answers.append(socket.inet_ntoa(rdata))
        if not answers:
            return None
        for ip in answers:
            try:
                ptr = await asyncio.wait_for(self.resolver.gethostbyaddr(ip), CHECK_TIMEOUT)
            except Exception:
                return None
            if AKAMAI_KEYWORD not in ptr.name.lower():
                logger.warning(f"{url} reject {ip} ptr {ptr.name}")
                return None
        logger.info(f"{url} ok {int(rtt)}ms")
        return rtt

    async def refresh(self):
        logger.info("refresh start")
        async with aiohttp.ClientSession() as session:
            tasks = [self.check_backend(session, u) for u in self.backends]
            results = await asyncio.gather(*tasks)
        candidates = [(u, r) for u, r in zip(self.backends, results) if r is not None]
        if not candidates:
            logger.error("no backend available")
            return
        candidates.sort(key=lambda x: x[1])
        async with self.lock:
            self.current = candidates[0][0]
        name = alias_of(self.current)
        logger.info(f"backend {self.current} {name} {int(candidates[0][1])}ms")

    async def get_backend(self):
        async with self.lock:
            return self.current

    async def loop_refresh(self):
        await asyncio.sleep(REFRESH_INTERVAL)
        while True:
            await self.refresh()
            await asyncio.sleep(REFRESH_INTERVAL)


class DohDNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, selector):
        self.selector = selector
        self.transport = None
        self.session = aiohttp.ClientSession()

    def connection_made(self, transport):
        self.transport = transport
        logger.info("dns server start")

    def datagram_received(self, data, addr):
        asyncio.create_task(self.handle_query(data, addr))

    async def handle_query(self, data, addr):
        backend = await self.selector.get_backend()
        if not backend:
            return
        try:
            async with self.session.post(
                    backend,
                    data=data,
                    headers={
                        "content-type": "application/dns-message",
                        "accept": "application/dns-message",
                    },
                    timeout=CHECK_TIMEOUT,
            ) as r:
                if r.status != 200:
                    return
                resp = await r.read()
        except Exception as e:
            logger.warning(f"query fail {e}")
            return
        self.transport.sendto(resp, addr)

    def connection_lost(self, exc):
        asyncio.create_task(self.session.close())
        logger.info("dns server stop")


async def main():
    selector = DohSelector(DOH_BACKENDS)
    await selector.refresh()
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DohDNSProtocol(selector),
        local_addr=("127.0.0.1", 53438),
    )
    refresher = asyncio.create_task(selector.loop_refresh())
    try:
        await asyncio.Future()
    finally:
        refresher.cancel()
        transport.close()


if __name__ == "__main__":
    asyncio.run(main())
