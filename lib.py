import base64
import logging
from typing import Callable, Optional
from urllib.parse import parse_qs, unquote, urlparse

import dns.exception
import dns.rdatatype
import dns.resolver


def b64decode(b: str) -> bytes:
    while len(b) % 4 != 0:
        b += "="
    return base64.urlsafe_b64decode(b)


class Parser:
    nameserver: Optional[str]
    resolver: dns.resolver.Resolver
    outbounds: list[dict]

    def __init__(self, nameserver: Optional[str] = None):
        self.nameserver = nameserver
        self.resolver = dns.resolver.Resolver()
        if self.nameserver is not None:
            self.resolver.nameservers = [self.nameserver]
        self.outbounds = []

    def resolve(self, host: str) -> str:
        if self.nameserver is None:
            return host
        try:
            logging.info("DNS query|%s" % (host))
            answers = self.resolver.resolve(
                host,
                rdtype=dns.rdatatype.A,
                tcp=True,
                raise_on_no_answer=False,
            )
            if not answers:
                logging.info("DNS no A answers")
                answers = self.resolver.resolve(
                    host,
                    rdtype=dns.rdatatype.AAAA,
                    tcp=True,
                    raise_on_no_answer=True,
                )
            answer = answers[0].to_text()
            logging.info("DNS answer|%s" % (answer))
            return answer
        except dns.exception.DNSException:
            logging.exception("DNS error")
            return host

    def parse(self, group_name: str, fn: Callable[[str, dict], bool]):
        def try_add(fragment, outbound):
            if fn(fragment, outbound):
                outbound["tag"] = f"[{group_name}] {fragment}"
                self.outbounds.append(outbound)
            else:
                logging.warning("filtered|%s" % (fragment))

        with open(f"run/{group_name}.txt") as f:
            share_links = b64decode(f.read()).decode("utf-8").splitlines()
        for share_link in share_links:
            try:
                parsed_url = urlparse(share_link)
            except ValueError:
                continue
            fragment = unquote(parsed_url.fragment, encoding="utf-8")
            query_params = parse_qs(parsed_url.query)
            match parsed_url.scheme:
                case "vless":
                    if (
                        query_params.get("encryption") == ["none"]
                        and query_params.get("type") == ["grpc"]
                        and query_params.get("headerType") == ["none"]
                        and query_params.get("security") == ["tls"]
                        and query_params.get("mode") == ["gun"]
                    ):
                        uuid, hostname_part = parsed_url.netloc.split("@", 1)
                        server, server_port = hostname_part.split(":", 1)
                        try_add(
                            fragment,
                            {
                                "type": "vless",
                                "server": self.resolve(server),
                                "server_port": int(server_port),
                                "uuid": uuid,
                                "tls": {
                                    "enabled": True,
                                    "server_name": query_params["sni"][0],
                                },
                                "transport": {
                                    "type": "grpc",
                                    "service_name": query_params["serviceName"][0],
                                },
                            },
                        )
                    else:
                        logging.warning(
                            "unknown vless|%s|%s" % (query_params, fragment)
                        )
                case "trojan":
                    uuid, hostname_part = parsed_url.netloc.split("@", 1)
                    server, server_port = hostname_part.split(":", 1)
                    try_add(
                        fragment,
                        {
                            "type": "trojan",
                            "server": server,
                            "server_port": int(server_port),
                            "password": uuid,
                            "tls": {
                                "enabled": True,
                                "insecure": query_params.get("allowInsecure", ["0"])
                                == ["1"],
                                "server_name": query_params["peer"][0],
                            },
                        },
                    )
                case _:
                    logging.warning(
                        "unknown proto|scheme=%s|%s" % (parsed_url.scheme, fragment)
                    )

    def assemble(self) -> list:
        outbounds = self.outbounds.copy()
        proxy_tags = []
        for o in outbounds:
            tag = o["tag"]
            count = 0
            while tag in proxy_tags:
                count += 1
                tag = o["tag"] + f" #{count}"
            o["tag"] = tag
            proxy_tags.append(tag)
        outbounds.extend(
            [
                {
                    "type": "selector",
                    "tag": "proxy",
                    "outbounds": ["auto"] + proxy_tags,
                    "interrupt_exist_connections": False,
                },
                {
                    "type": "urltest",
                    "tag": "auto",
                    "outbounds": proxy_tags,
                    "interval": "1m",
                    "tolerance": 50,
                    "interrupt_exist_connections": False,
                },
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"},
                {"type": "dns", "tag": "dns-out"},
            ]
        )
        return outbounds
