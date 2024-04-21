#!/usr/bin/env python
import json
import os
from typing import Annotated, Self

import typer

from common import setup_logging
from lib import BaseProvider, FilterResult, Parser


class OkggProvider(BaseProvider):
    def __init__(self):
        super().__init__("okgg", "https://rss.okggrss.top/link/3tddh0FHKbzOdLoE?mu=2")


class WwProvider(BaseProvider):
    def __init__(self):
        super().__init__("ww", "https://ww5271.xyz/rss/mEWrAf3/D7jmP8?net_type=TROJAN")

    def filter(self, name: str) -> FilterResult:
        if "游戏" in name:
            return []
        return super().filter(name.split("·")[1])


def get_providers(names: list[str]) -> list[BaseProvider]:
    providers = []
    for name in names:
        match name:
            case "okgg":
                providers.append(OkggProvider())
            case "ww":
                providers.append(WwProvider())
    return providers


# "domain_suffix": [
#    ".archlinux.org",
#    ".bopufund.com",
#    "ftiasch.xyz",
#    ".limao.tech",
#    ".ntp.org",
# ],
class Gen:
    nameserver: str
    providers: list[BaseProvider]
    rule_sets: set[str]
    config: dict

    def __init__(self: Self, nameserver: str, providers: list[BaseProvider]) -> None:
        self.nameserver = nameserver
        self.providers = providers

        self.rule_sets = set()
        self.config = {}
        self.config = {
            "log": {"level": "error", "timestamp": True},
            "dns": {
                "servers": [
                    {"tag": "reject-dns", "address": "rcode://refused"},
                    {
                        "tag": "cloudflare-doh",
                        "address": "https://1.1.1.1/dns-query",
                        "address_resolver": "aliyun-doh",
                        "detour": "PROXY",
                    },
                    {
                        "tag": "aliyun-doh",
                        "address": "https://223.5.5.5/dns-query",
                        "detour": "direct-out",
                    },
                ],
                "rules": [
                    {"server": "fakeip-dns", "clash_mode": "Global"},
                    {"server": "aliyun-doh", "clash_mode": "Direct"},
                    {"server": "reject-dns", "rule_set": self.__rule_set(["reject"])},
                    {
                        "server": "cloudflare-doh",
                        "rule_set": ["telegramcidr", "google", "proxy"],
                    },
                    {
                        "server": "aliyun-doh",
                        "rule_set": self.__rule_set(
                            [
                                "geoip-cn",
                                "applications",
                                "icloud",
                                "apple",
                                "direct",
                                "lancidr",
                                "cncidr",
                            ]
                        ),
                    },
                ],
                "independent_cache": True,
                "final": "cloudflare-doh",
            },
            "route": {
                "rule_set": None,
                "rules": [
                    {"outbound": "direct-out", "ip_is_private": True},
                    {
                        "outbound": "dns-out",
                        "type": "logical",
                        "mode": "or",
                        "rules": [
                            {"port": 5353},
                            # {"protocol": "dns"},
                            {"inbound": ["dns-in"]},
                        ],
                    },
                    {
                        "outbound": "reject-out",
                        "type": "logical",
                        "mode": "or",
                        "rules": [{"port": 853}, {"protocol": "stun"}],
                    },
                    {"outbound": "PROXY", "clash_mode": "Global"},
                    {"outbound": "direct-out", "clash_mode": "Direct"},
                    {"outbound": "reject-out", "rule_set": ["reject"]},
                    {
                        "outbound": "direct-out",
                        "type": "logical",
                        "mode": "and",
                        "rules": [
                            {
                                "invert": True,
                                "rule_set": self.__rule_set(
                                    ["telegramcidr", "google", "proxy"]
                                ),
                            },
                            {
                                "rule_set": self.__rule_set(
                                    [
                                        "geoip-cn",
                                        "applications",
                                        "icloud",
                                        "apple",
                                        "direct",
                                        "lancidr",
                                        "cncidr",
                                    ]
                                )
                            },
                        ],
                    },
                ],
                "auto_detect_interface": True,
                "final": "PROXY",
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
                    "external_ui_download_detour": "PROXY",
                },
            },
        }
        self.config["outbounds"] = self.__get_outbounds()
        self.config["route"]["rule_set"] = self.__get_rule_set()

    def __get_outbounds(self: Self) -> list[dict]:
        return []

    @staticmethod
    def get_rule_set_url(r: str) -> str:
        if r == "geoip-cn":
            return "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
        return "https://raw.githubusercontent.com/chg1f/sing-geosite-mixed/rule-set/{r}.srs"

    def __get_rule_set(self: Self) -> list[dict]:
        result = []
        for r in self.rule_sets:
            result.append(
                {
                    "tag": r,
                    "type": "remote",
                    "download_detour": "PROXY",
                    "update_interval": "1d",
                    "format": "binary",
                    "url": self.get_rule_set_url(r),
                }
            )
        return result

    def __rule_set(self: Self, names: list[str]) -> list[str]:
        for name in names:
            self.rule_sets.add(name)
        return names


DEFAULT_NAMESERVER = "223.5.5.5"
DEFAULT_PROVIDERS = ["okgg", "ww"]

app = typer.Typer(pretty_exceptions_enable=False)


def setup() -> None:
    os.chdir(os.path.dirname(__file__) or ".")
    setup_logging()
    os.makedirs("run", exist_ok=True)


@app.command()
def down(
    *,
    nameserver: str = DEFAULT_NAMESERVER,
    ipv6: bool = False,
    provider_names: Annotated[
        list[str], typer.Option("--provider", "-p")
    ] = DEFAULT_PROVIDERS,
):
    setup()

    providers = get_providers(provider_names)

    # for p in providers:
    #     p.download()

    parser = Parser(nameserver=nameserver, ipv6=ipv6)
    for p in providers:
        parser.parse(p)

    with open("run/outbounds.json", "w") as f:
        json.dump(parser.get_outbounds(), f, ensure_ascii=False, indent=4)


# @app.command()
# def gen(
#     *,
#     download: bool = False,
#     nameserver: str = DEFAULT_NAMESERVER,
#     provider: Annotated[list[str], typer.Option()] = DEFAULT_PROVIDERS,
# ):
#     os.chdir(os.path.dirname(__file__) or ".")
#     setup_logging()
#
#     gen = Gen(
#         nameserver=nameserver, providers=[p for p in PROVIDERS if p.name in provider]
#     )
#
#     if download:
#         gen.download()
#
#     gen.gen()
#
#     with open("run/config.json", "w") as f:
#         json.dump(gen.config, f, ensure_ascii=False, indent=4)


if __name__ == "__main__":
    app()
