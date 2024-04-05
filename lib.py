import base64
from collections import defaultdict
import logging
from typing import Callable, Optional
from urllib.parse import parse_qs, unquote, urlparse
import re

import dns.exception
import dns.rdatatype
import dns.resolver
import dns.nameserver


def b64decode(b: str) -> bytes:
    while len(b) % 4 != 0:
        b += "="
    return base64.urlsafe_b64decode(b)


def is_valid_ip(ip):
    ipv4_pattern = re.compile(
        r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    ipv6_pattern = re.compile("^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4})$")
    return bool(ipv4_pattern.match(ip)) or bool(ipv6_pattern.match(ip))


def auto(g: str) -> str:
    return g + " auto"


class Parser:
    nameserver: Optional[dns.nameserver.Nameserver]
    ipv6: bool
    resolver: dns.resolver.Resolver
    outbounds: list[tuple[list[list[str]], dict]]

    def __init__(
        self, nameserver: Optional[dns.nameserver.Nameserver] = None, ipv6=False
    ):
        self.nameserver = nameserver
        self.ipv6 = ipv6
        self.resolver = dns.resolver.Resolver()
        if self.nameserver is not None:
            self.resolver.nameservers = [self.nameserver]
        self.outbounds = []
        self.groups = {}

    def resolve(self, host: str) -> Optional[str]:
        if self.nameserver is None or is_valid_ip(host):
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
                if self.ipv6:
                    logging.info("DNS no A answers")
                    answers = self.resolver.resolve(
                        host,
                        rdtype=dns.rdatatype.AAAA,
                        tcp=True,
                        raise_on_no_answer=True,
                    )
                else:
                    return None
            answer = answers[0].to_text()
            logging.info("DNS answer|%s" % (answer))
            return answer
        except dns.exception.DNSException:
            logging.exception("DNS error")
            return None

    def has_tag(self, tag: str):
        for _, o in self.outbounds:
            if o["tag"] == tag:
                return True
        return False

    def get_tag(self, otag: str) -> str:
        count, tag = 0, otag
        while self.has_tag(tag):
            count += 1
            tag = otag + f" #{count}"
        return tag

    def parse(self, group_name: str, fn: Callable[[str, dict], list[list[str]]]):
        def try_add(fragment, outbound):
            paths = fn(fragment, outbound)
            if paths:
                outbound["tag"] = self.get_tag(fragment)
                self.outbounds.append((paths, outbound))
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
                        server = self.resolve(server)
                        if server:
                            try_add(
                                fragment,
                                {
                                    "type": "vless",
                                    "server": server,
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
        groups, auto_groups, outbounds = defaultdict(set), defaultdict(set), []
        for paths, o in self.outbounds:
            outbounds.append(o)
            for path in paths:
                for u, v in zip(path, path[1:]):
                    groups[u].add(v)
                    auto_groups[auto(u)].add(auto(v))
                u, tag = path[-1], o["tag"]
                groups[u].add(tag)
                auto_groups[auto(u)].add(tag)

        for group, children in groups.items():
            outbounds.append(
                {
                    "type": "selector",
                    "tag": group,
                    "outbounds": [auto(group), *children],
                    "default": auto(group),
                    "interrupt_exist_connections": False,
                },
            )
        for group, children in auto_groups.items():
            outbounds.append(
                {
                    "type": "urltest",
                    "tag": group,
                    "outbounds": list(children),
                    "interval": "5m",
                    "tolerance": 100,
                    "interrupt_exist_connections": True,
                },
            )

        outbounds.extend(
            [
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"},
                {"type": "dns", "tag": "dns-out"},
            ]
        )
        return outbounds
