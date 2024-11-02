#!/usr/bin/env python
import json
import os
from typing import IO, Annotated, Any

import typer

from .common import setup_logging
from .lib import BaseProvider, FilterResult, Parser


class OkggProvider(BaseProvider):
    def __init__(self):
        super().__init__("okgg", "https://rss.okxyz.xyz/link/nPsuuOMh6xq1lyS5?mu=2")

    def filter(self, proxy_tag: str, proto: str, name: str) -> FilterResult:
        if proto == "ss":
            return []
        region = BaseProvider.guess_region(name)
        if region not in ("US", "HK", "JP", "SG", "TW", "ID", "TH", "PH"):
            return []
        return [[proxy_tag, self.name]]


class WwProvider(BaseProvider):
    def __init__(self):
        super().__init__("ww", "https://ww5271.xyz/rss/mEWrAf3/D7jmP8?net_type=TROJAN")

    def filter(self, proxy_tag: str, proto: str, name: str) -> FilterResult:
        if "游戏" in name:
            return []
        region = BaseProvider.guess_region(name.split("·")[1])
        if region not in ("US", "HK", "JP", "SG", "TW", "ID", "TH", "PH"):
            return []
        tags = [[proxy_tag, self.name]]
        if "GPT" in name:
            tags.append(["gpt-out"])
        if "流媒体" in name:
            tags.append(["video-out"])
        return tags


class SsrDogProvider(BaseProvider):
    def __init__(self):
        super().__init__(
            "ssrdog",
            "https://no1-svip.api-baobaog.rest/s?t=75c680c64ec9ab655585fe6712da4fe2",
        )


def get_providers(names: list[str]) -> list[BaseProvider]:
    providers = []
    for name in names:
        match name:
            case "okgg":
                providers.append(OkggProvider())
            case "ww":
                providers.append(WwProvider())
            case "ssrdog":
                providers.append(SsrDogProvider())
    return providers


class Gen:
    providers: list[BaseProvider]
    download_detour: str
    ghproxy: bool

    rule_sets: set[str]
    config: dict

    def __init__(
        self, providers: list[BaseProvider], download_detour: str, ghproxy: bool
    ) -> None:
        self.providers = providers
        self.download_detour = download_detour
        self.ghproxy = ghproxy
        self.rule_sets = set()

        def rule_set(names: list[str]) -> list[str]:
            return self.__rule_set(names)

        def route(outbound: str, **kwargs) -> dict:
            return {
                **kwargs,
                "outbound": outbound,
            }

        def route_direct(**kwargs) -> dict:
            return route("direct-out", **kwargs)

        ensure_proxy = rule_set(["geosite-bing", "geosite-github"])
        ensure_direct = rule_set(
            [
                "geosite-adobe",
                "geosite-adobe-activation",
                "geosite-apple",
                "geosite-geolocation-cn",
                "geosite-microsoft",
                "geosite-steam",
            ]
        )

        outbounds = self.__get_outbounds()
        tags = [o["tag"] for o in outbounds]
        self.config = {
            "log": {"level": "error", "timestamp": True},
            "dns": {
                "servers": [
                    {"tag": "reject-dns", "address": "rcode://refused"},
                    {
                        "tag": "domestic-dns",
                        "address": "127.0.0.1:6053",
                        "strategy": "ipv4_only",
                        "detour": "direct-out",
                    },
                    {
                        "tag": "lan-dns",
                        "address": "127.0.0.1:54",
                        "strategy": "ipv4_only",
                        "detour": "direct-out",
                    },
                    {
                        "tag": "oversea-dns",
                        "address": "tls://8.8.8.8",
                        "strategy": "ipv4_only",
                        "detour": "proxy-out",
                    },
                ],
                "rules": [
                    {"outbound": "any", "server": "domestic-dns"},
                    {
                        "domain_suffix": ["lan"],
                        "server": "lan-dns",
                    },
                    {
                        "rule_set": ensure_proxy,
                        "server": "oversea-dns",
                    },
                    {
                        "rule_set": ensure_direct,
                        "server": "domestic-dns",
                    },
                ],
                "final": "oversea-dns",
                "independent_cache": True,
            },
            "route": {
                "rule_set": None,
                "rules": [
                    route("dns-out", inbound="dns-in"),
                    route_direct(inbound="http-direct-in"),
                    route_direct(ip_is_private=True),
                    *(
                        [route("gpt-out", rule_set=rule_set(["geosite-openai"]))]
                        if "gpt-out" in tags
                        else []
                    ),
                    *(
                        [route("video-out", rule_set=rule_set(["geosite-youtube"]))]
                        if "video-out" in tags
                        else []
                    ),
                    route("proxy-out", rule_set=ensure_proxy),
                    route_direct(rule_set=rule_set(["geoip-cn"]) + ensure_direct),
                    route_direct(port=[123]),
                    route_direct(
                        source_ip_cidr=[
                            "192.168.1.120",
                            "192.168.1.182",
                            "192.168.1.183",
                            "192.168.1.185",
                            "192.168.1.215",
                            "192.168.1.221",
                        ]  # Mijia Cloud
                    ),
                ],
                "final": "proxy-out",
                "auto_detect_interface": True,
            },
            "inbounds": [
                {
                    "type": "direct",
                    "tag": "dns-in",
                    "listen": "0.0.0.0",
                    "listen_port": 53,
                    "network": "udp",
                    "override_address": "1.0.0.1",
                    "override_port": 53,
                },
                {
                    "type": "tun",
                    "tag": "tun-in",
                    # "mtu": 1492,
                    # "gso": True,
                    "address": ["172.19.0.1/30"],
                    "auto_route": True,
                    "strict_route": False,
                    "stack": "system",
                    "sniff": True,
                },
                {"type": "http", "tag": "http-in", "listen": "::", "listen_port": 8001},
                {
                    "type": "http",
                    "tag": "http-direct-in",
                    "listen": "::",
                    "listen_port": 8002,
                },
            ],
            "outbounds": None,
            "experimental": {
                "cache_file": {
                    "enabled": True,
                    "path": "cache.db",
                    "store_fakeip": True,
                },
                "clash_api": {
                    "external_controller": "0.0.0.0:9090",
                    "external_ui": "/usr/share/yacd-meta",
                },
            },
        }
        self.config["outbounds"] = outbounds
        self.config["route"]["rule_set"] = self.__get_rule_set()

    def __get_outbounds(self) -> list[dict]:
        with open("run/outbounds.json") as f:
            outbounds: list[dict] = json.load(f)
        return [
            {"type": "direct", "tag": "direct-out"},
            {"type": "block", "tag": "reject-out"},
            {"type": "dns", "tag": "dns-out"},
        ] + outbounds

    def proxy_url(self, u: str) -> str:
        if self.ghproxy:
            return "https://ghp.ci/" + u
        return u

    def get_rule_set_url(self, r: str) -> str:
        if r.startswith("geoip"):
            url = f"https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/{r}.srs"
        else:
            url = f"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/{r}.srs"
        return self.proxy_url(url)

    def __get_rule_set(self) -> list[dict]:
        result = []
        for r in self.rule_sets:
            result.append(
                {
                    "tag": r,
                    "type": "remote",
                    "download_detour": self.download_detour,
                    "update_interval": "1d",
                    "format": "binary",
                    "url": self.get_rule_set_url(r),
                }
            )
        return result

    def __rule_set(self, names: list[str]) -> list[str]:
        for name in names:
            self.rule_sets.add(name)
        return names


DEFAULT_NAMESERVER = "223.5.5.5"
DEFAULT_PROVIDERS = ["okgg", "ww"]

app = typer.Typer(pretty_exceptions_enable=False)


def dump(obj: Any, f: IO):
    json.dump(obj, f, ensure_ascii=False, indent=4)


@app.command()
def main(
    *,
    download: bool = False,
    nameserver: str = DEFAULT_NAMESERVER,
    ipv6: bool = False,
    provider_names: Annotated[list[str], typer.Option("--provider", "-p")] = [],
    download_detour: Annotated[str, typer.Option("-dd")] = "direct-out",
    ghproxy: bool = True,
):
    setup_logging()
    os.makedirs("run", exist_ok=True)

    providers = get_providers(provider_names)

    if download:
        for p in providers:
            p.download()

    parser = Parser(nameserver=nameserver, ipv6=ipv6, proxy_tag="proxy-out")
    for p in providers:
        parser.parse(p)
    with open("run/outbounds.json", "w") as f:
        dump(parser.get_outbounds(), f)

    gen = Gen(providers, download_detour=download_detour, ghproxy=ghproxy)
    with open("run/config.json", "w") as f:
        dump(gen.config, f)


if __name__ == "__main__":
    app()
