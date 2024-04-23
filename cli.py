#!/usr/bin/env python
import json
import os
from typing import IO, Annotated, Any

import typer

from common import setup_logging
from lib import BaseProvider, FilterResult, Parser


class OkggProvider(BaseProvider):
    def __init__(self):
        super().__init__("okgg", "https://rss.okggrss.top/link/3tddh0FHKbzOdLoE?mu=2")


class WwProvider(BaseProvider):
    def __init__(self):
        super().__init__("ww", "https://ww5271.xyz/rss/mEWrAf3/D7jmP8?net_type=TROJAN")

    def filter(self, proxy_tag: str, name: str) -> FilterResult:
        if "游戏" in name:
            return []
        return super().filter(proxy_tag, name.split("·")[1])


def get_providers(names: list[str]) -> list[BaseProvider]:
    providers = []
    for name in names:
        match name:
            case "okgg":
                providers.append(OkggProvider())
            case "ww":
                providers.append(WwProvider())
    return providers


PROXY_TAG = "PROXY"


class Gen:
    providers: list[BaseProvider]
    download_detour: str
    ghproxy: bool

    rule_sets: set[str]
    config: dict

    @staticmethod
    def to_domains(domains: list[str]) -> dict:
        return {
            "domain": domains,
            "domain_suffix": ["." + domain for domain in domains],
        }

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

        use_ip = {
            "domain": ["sz.bopufund.com" "ftiasch.xyz", "limao.tech"],
            "domain_suffix": [
                ".ftiasch.xyz",
                ".limao.tech",
            ],
        }

        self.config = {
            "log": {"level": "error", "timestamp": True},
            "dns": {
                "servers": [
                    {"tag": "fakeip-dns", "address": "fakeip"},
                    {"tag": "reject-dns", "address": "rcode://refused"},
                    {
                        "tag": "domestic-dns",
                        "address": "tls://1.12.12.12",
                        "strategy": "ipv4_only",
                        "detour": "direct-out",
                    },
                ],
                "rules": [
                    {"outbound": "any", "server": "domestic-dns"},
                    {**use_ip, "server": "domestic-dns"},
                    {"query_type": ["A"], "server": "fakeip-dns"},
                ],
                "final": "reject-dns",
                "fakeip": {
                    "enabled": True,
                    "inet4_range": "10.32.0.0/12",
                },
                "independent_cache": True,
            },
            "route": {
                "rule_set": None,
                "rules": [
                    route("dns-out", inbound="dns-in"),
                    route_direct(inbound="http-direct-in"),
                    route(PROXY_TAG, ip_cidr=["13.115.121.128"]),
                    route_direct(ip_is_private=True),
                    route_direct(
                        rule_set=rule_set(
                            [
                                "geosite-private",
                                "geosite-apple",
                                "geosite-steam",
                                "geosite-tld-cn",
                                "geosite-category-games@cn",
                            ]
                        )
                    ),
                    route_direct(
                        **self.to_domains(
                            [
                                "linksyssmartwifi.com",
                                "syncthing.net",
                                # misa's
                                "moecube.com",
                                "jihuanshe.com",
                                "ygobbs.com",
                            ]
                        )
                    ),
                    route(PROXY_TAG, rule_set=rule_set(["geosite-geolocation-!cn"])),
                    route_direct(
                        rule_set=rule_set(
                            [
                                "geoip-cn",
                                "geosite-cn",
                            ]
                        )
                    ),
                ],
                "final": PROXY_TAG,
                "auto_detect_interface": True,
            },
            "inbounds": [
                {
                    "type": "direct",
                    "tag": "dns-in",
                    "listen": "127.0.0.1",
                    "listen_port": 5353,
                    "network": "udp",
                    "override_address": "1.0.0.1",
                    "override_port": 53,
                },
                {
                    "type": "tun",
                    "tag": "tun-in",
                    "mtu": 1492,
                    "gso": True,
                    "inet4_address": "172.19.0.1/30",
                    "auto_route": True,
                    "strict_route": True,
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
                    "external_ui_download_detour": self.download_detour,
                },
            },
        }
        self.config["outbounds"] = self.__get_outbounds()
        self.config["route"]["rule_set"] = self.__get_rule_set()

    def __get_outbounds(self) -> list[dict]:
        with open("run/outbounds.json") as f:
            outbounds: list[dict] = json.load(f)
        return [
            {"type": "direct", "tag": "direct-out"},
            {"type": "block", "tag": "reject-out"},
            {"type": "dns", "tag": "dns-out"},
        ] + outbounds

    def get_rule_set_url(self, r: str) -> str:
        if r.startswith("geoip"):
            url = f"https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/{r}.srs"
        else:
            url = f"https://raw.githubusercontent.com/chg1f/sing-geosite-mixed/rule-set/{r}.srs"
        if self.ghproxy:
            return "https://mirror.ghproxy.com/" + url
        return url

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
    provider_names: Annotated[
        list[str], typer.Option("--provider", "-p")
    ] = DEFAULT_PROVIDERS,
    download_detour: Annotated[str, typer.Option("-dd")] = "direct-out",
    ghproxy: bool = True,
):
    os.chdir(os.path.dirname(__file__) or ".")
    setup_logging()
    os.makedirs("run", exist_ok=True)

    providers = get_providers(provider_names)

    if download:
        for p in providers:
            p.download()

    parser = Parser(nameserver=nameserver, ipv6=ipv6, proxy_tag=PROXY_TAG)
    for p in providers:
        parser.parse(p)
    with open("run/outbounds.json", "w") as f:
        dump(parser.get_outbounds(), f)

    gen = Gen(providers, download_detour=download_detour, ghproxy=ghproxy)
    with open("run/config.json", "w") as f:
        dump(gen.config, f)


if __name__ == "__main__":
    app()
