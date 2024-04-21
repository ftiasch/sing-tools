import base64
import logging
import re
from collections import defaultdict
from typing import Optional, TypeAlias
from urllib.parse import parse_qs, unquote, urlparse

import dns.exception
import dns.nameserver
import dns.rdatatype
import dns.resolver
import requests


def _b64decode(b: str) -> bytes:
    while len(b) % 4 != 0:
        b += "="
    return base64.urlsafe_b64decode(b)


def _is_valid_ip(ip):
    ipv4_pattern = re.compile(
        r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    ipv6_pattern = re.compile("^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4})$")
    return bool(ipv4_pattern.match(ip)) or bool(ipv6_pattern.match(ip))


def _auto(g: str) -> str:
    return g + " auto"


FilterResult: TypeAlias = list[list[str]]


class BaseProvider:
    name: str
    url: str

    def __init__(self, name: str, url: str):
        self.name, self.url = name, url

    @staticmethod
    def guess_region(name: str) -> str:
        config = {
            "US": ["US", "美国"],
            "HK": ["HongKong", "HK", "港", "🇭🇰"],
            "JP": ["Osaka", "JP", "日", "🇯🇵"],
            "SG": ["Singapore", "新加坡"],
            "TW": ["TW"],
            "KR": ["KR"],
            "MY": [
                "吉隆坡",
                "🇲🇾",
            ],
            "TH": [
                "曼谷",
                "🇹🇭",
            ],
            "PH": [
                "马尼拉",
                "🇵🇭",
            ],
        }
        for region, matchers in config.items():
            for matcher in matchers:
                if matcher in name:
                    return region
        return "N/A"

    def filter(self, proxy_tag: str, name: str) -> FilterResult:
        region = BaseProvider.guess_region(name)
        if region not in ("US", "HK", "JP", "SG", "TW", "TH", "PH"):
            return []
        tags = [[proxy_tag, self.name]]
        if region in ("US", "JP", "SG", "TW"):
            tags.append(["openai"])
        return tags

    def download(self) -> None:
        name, url = self.name, self.url
        logging.info("Downloading %s from %s", name, url)
        try:
            content = requests.get(url).text
        except Exception:
            logging.exception("")
            return
        with open(f"run/{name}.txt", "w") as f:
            f.write(content)


class Parser:
    nameserver: Optional[str | dns.nameserver.Nameserver]
    ipv6: bool
    proxy_tag: str
    resolver: dns.resolver.Resolver
    outbounds: list[tuple[list[list[str]], dict]]

    def __init__(
        self,
        *,
        nameserver: Optional[str | dns.nameserver.Nameserver] = None,
        ipv6=False,
        proxy_tag: str,
    ):
        self.nameserver = nameserver
        self.ipv6 = ipv6
        self.proxy_tag = proxy_tag
        self.resolver = dns.resolver.Resolver()
        if self.nameserver is not None:
            self.resolver.nameservers = [self.nameserver]
        self.outbounds = []
        self.groups = {}

    def __resolve(self, host: str) -> Optional[str]:
        if self.nameserver is None or _is_valid_ip(host):
            return host
        try:
            logging.info("DNS query|%s", host)
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
            answer = answers[0].to_text()  # type: ignore
            logging.info("DNS answer|%s", answer)
            return answer
        except dns.exception.DNSException:
            logging.exception("DNS error")
            return None

    def __has_tag(self, tag: str):
        for _, o in self.outbounds:
            if o["tag"] == tag:
                return True
        return False

    def __get_tag(self, otag: str) -> str:
        count, tag = 0, otag
        while self.__has_tag(tag):
            count += 1
            tag = otag + f" #{count}"
        return tag

    def parse(self, provider: BaseProvider):
        def try_add(fragment, outbound):
            paths = provider.filter(self.proxy_tag, fragment)
            if paths:
                outbound["tag"] = self.__get_tag(fragment)
                self.outbounds.append((paths, outbound))
            else:
                logging.warning("filtered|%s", fragment)

        with open(f"run/{provider.name}.txt") as f:
            share_links = _b64decode(f.read()).decode("utf-8").splitlines()
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
                        server = self.__resolve(server)
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
                        logging.warning("unknown vless|%s|%s", query_params, fragment)
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
                        "unknown proto|scheme=%s|%s", parsed_url.scheme, fragment
                    )

    def get_outbounds(self) -> list[dict]:
        groups, auto_groups, outbounds = defaultdict(set), defaultdict(set), []
        for paths, o in self.outbounds:
            outbounds.append(o)
            for path in paths:
                for u, v in zip(path, path[1:]):
                    groups[u].add(v)
                    auto_groups[_auto(u)].add(_auto(v))
                u, tag = path[-1], o["tag"]
                groups[u].add(tag)
                auto_groups[_auto(u)].add(tag)

        for group, children in groups.items():
            outbounds.append(
                {
                    "type": "selector",
                    "tag": group,
                    "outbounds": [_auto(group), *children],
                    "default": _auto(group),
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

        return outbounds
