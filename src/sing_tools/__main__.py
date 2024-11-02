#!/usr/bin/env python
import json
import os
from typing import IO, Annotated, Any

import typer

from .common import setup_logging
from .lib import BaseGen, BaseProvider, FilterResult, Parser


class OkggProvider(BaseProvider):
    def __init__(self):
        super().__init__("okgg", "https://rss.okxyz.xyz/link/nPsuuOMh6xq1lyS5?mu=2")

    def filter(self, proto: str, name: str) -> FilterResult:
        if proto == "ss":
            return []
        region = BaseProvider.guess_region(name)
        if region not in ("US", "HK", "JP", "SG", "TW", "ID", "TH", "PH"):
            return []
        return [["proxy-out", self.name]]


class WwProvider(BaseProvider):
    def __init__(self):
        super().__init__("ww", "https://ww5271.xyz/rss/mEWrAf3/D7jmP8?net_type=TROJAN")

    def filter(self, proto: str, name: str) -> FilterResult:
        if "游戏" in name:
            return []
        region = BaseProvider.guess_region(name.split("·")[1])
        if region not in ("US", "HK", "JP", "SG", "TW", "ID", "TH", "PH"):
            return []
        tags = [["proxy-out", self.name]]
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


class Gen(BaseGen):
    def override(self):
        ensure_proxy = [self.rule_set("geosite-bing"), self.rule_set("geosite-github")]
        ensure_direct = [
            self.rule_set("geosite-adobe"),
            self.rule_set("geosite-adobe-activation"),
            self.rule_set("geosite-apple"),
            self.rule_set("geosite-geolocation-cn"),
            self.rule_set("geosite-microsoft"),
            self.rule_set("geosite-steam"),
        ]
        self.config["dns"]["servers"].extend(
            [
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
            ]
        )
        self.config["dns"]["rules"].extend(
            [
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
            ]
        )
        self.config["dns"]["final"] = "oversea-dns"
        if "gpt-out" in self.parser.tags:
            self.config["route"]["rules"].append(
                {"outbound": "gpt-out", "rule_set": [self.rule_set("geosite-openai")]}
            )
        if "video-out" in self.parser.tags:
            self.config["route"]["rules"].append(
                {
                    "outbound": "video-out",
                    "rule_set": [self.rule_set("geosite-youtube")],
                }
            )
        self.config["route"]["rules"].extend(
            [
                {
                    "outbound": "proxy-out",
                    "rule_set": ensure_proxy,
                },
                {
                    "outbound": "direct-out",
                    "rule_set": [self.rule_set("geoip-cn")] + ensure_direct,
                },
                {"outbound": "direct-out", "port": [123]},
                {
                    "outbound": "direct-out",
                    "source_ip_cidr": [
                        "192.168.1.120",
                        "192.168.1.182",
                        "192.168.1.183",
                        "192.168.1.185",
                        "192.168.1.215",
                        "192.168.1.221",
                    ],  # Mijia Cloud
                },
            ]
        )
        self.config["route"]["final"] = "proxy-out"


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
    download_detour: Annotated[str, typer.Option("--dd")] = "direct-out",
    ghproxy: bool = True,
):
    setup_logging()
    os.makedirs("run", exist_ok=True)

    providers = get_providers(provider_names)

    if download:
        for p in providers:
            p.download()

    parser = Parser(nameserver=nameserver, ipv6=ipv6)
    for p in providers:
        parser.parse(p)
    with open("run/outbounds.json", "w") as f:
        dump(parser.get_outbounds(), f)

    gen = Gen(parser, download_detour=download_detour, ghproxy=ghproxy)
    gen.override()
    with open("run/config.json", "w") as f:
        dump(gen.get_config(), f)


if __name__ == "__main__":
    app()
