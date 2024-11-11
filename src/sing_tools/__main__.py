#!/usr/bin/env python
import json
import os
from typing import IO, Annotated, Any, override

import typer

from .common import setup_logging
from .lib import BaseGen, BaseProvider, FilterResult, Parser


class OkggProvider(BaseProvider):
    def __init__(self):
        super().__init__("okgg", "https://rss.okxyz.xyz/link/nPsuuOMh6xq1lyS5?mu=2")

    @override
    def filter(self, proto: str, name: str) -> FilterResult:
        if proto == "ss":
            return []
        tags = [["proxy-out", self.name], ["video-out"]]
        if BaseProvider.guess_region(name) not in ("HK",):
            tags.append(["gpt-out"])
        return tags

        # if region not in ("US", "HK", "JP", "SG", "TW", "ID", "TH", "PH"):
        #     return []


class WwProvider(BaseProvider):
    def __init__(self):
        super().__init__("ww", "https://ww5271.xyz/rss/mEWrAf3/D7jmP8?net_type=TROJAN")

    @override
    def filter(self, proto: str, name: str) -> FilterResult:
        if "游戏" in name:
            return [["game-out"]]
        if "GPT" in name:
            return [["gpt-out"]]
        if "流媒体" in name:
            return [["video-out"]]
        return [["proxy-out", self.name]]


class SsrDogProvider(BaseProvider):
    def __init__(self):
        super().__init__(
            "ssrdog",
            "https://no1-svip.api-baobaog.rest/s?t=75c680c64ec9ab655585fe6712da4fe2",
        )

    @override
    def filter(self, proto: str, name: str) -> FilterResult:
        tags = [["proxy-out", self.name]]
        if BaseProvider.guess_region(name) not in ("HK",):
            tags.append(["gpt-out"])
        return tags


def get_providers(names: list[str]) -> list[BaseProvider]:
    providers: list[BaseProvider] = []
    for name in names:
        match name:
            case "okgg":
                providers.append(OkggProvider())
            case "ww":
                providers.append(WwProvider())
            case "ssrdog":
                providers.append(SsrDogProvider())
            case _:
                pass
    return providers


class DomainRules:
    valid_tags: set[str]
    tags: set[str]
    rules: list[tuple[str, dict[str, Any]]]

    def __init__(self, valid_tags: set[str]):
        self.valid_tags = valid_tags
        self.tags = set()
        self.rules = []

    def add(self, tag: str, **kwargs):
        if tag == "direct" or (tag + "-out") in self.valid_tags:
            self.tags.add(tag)
            self.rules.append((tag, kwargs))

    @property
    def dns_servers(self):
        for tag in self.tags:
            yield {
                "tag": tag + "-dns",
                "address": "127.0.0.1:6053" if tag == "direct" else "tls://8.8.8.8",
                "strategy": "ipv4_only",
                "detour": tag + "-out",
            }

    @property
    def dns_rules(self):
        for tag, rule in self.rules:
            yield {"server": tag + "-dns", **rule}

    @property
    def route_rules(self):
        for tag, rule in self.rules:
            yield {"outbound": tag + "-out", **rule}


class Gen(BaseGen):
    def override(self):
        dr = DomainRules(self.valid_tags)
        dr.add("gpt", rule_set=self.rule_set("geosite-openai"))
        dr.add("gpt", domain_suffix=["perplexity.ai"])
        dr.add("video", rule_set=self.rule_set("geosite-youtube"))
        dr.add("proxy", rule_set=self.rule_sets(["geosite-bing", "geosite-github"]))
        dr.add(
            "direct",
            rule_set=self.rule_sets(
                [
                    "geosite-adobe",
                    "geosite-adobe-activation",
                    "geosite-apple",
                    "geosite-geolocation-cn",
                    "geosite-microsoft",
                    "geosite-steam@cn",
                ]
            ),
        )
        dr.add("game", rule_set=self.rule_set("geosite-steam"))
        self.config["dns"]["servers"].extend(
            [
                {
                    "tag": "lan-dns",
                    "address": "127.0.0.1:54",
                    "strategy": "ipv4_only",
                    "detour": "direct-out",
                },
            ]
            + list(dr.dns_servers)
        )
        self.config["dns"]["rules"].extend(
            [
                {
                    "server": "lan-dns",
                    "domain_suffix": ["lan"],
                },
                {
                    "server": "reject-dns",
                    "rule_set": self.rule_set("geosite-category-ads"),
                },
            ]
            + list(dr.dns_rules)
        )
        self.config["dns"]["final"] = "proxy-dns"

        self.config["route"]["rules"].extend(
            list(dr.route_rules)
            + [
                {
                    "outbound": "direct-out",
                    "rule_set": self.rule_set("geoip-cn"),
                },
                {"outbound": "direct-out", "port": [123]},
                {
                    "outbound": "direct-out",
                    "source_ip_cidr": [
                        "192.168.1.120",
                        "192.168.1.129",
                        "192.168.1.136",
                        "192.168.1.154",
                        "192.168.1.182",
                        "192.168.1.183",
                        "192.168.1.184",
                        "192.168.1.185",
                        "192.168.1.205",
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
    provider_names: Annotated[list[str] | None, typer.Option("--provider", "-p")],
    download_detour: Annotated[str, typer.Option("--dd")] = "direct-out",
    ghproxy: bool = True,
):
    setup_logging()
    os.makedirs("run", exist_ok=True)

    providers = get_providers(provider_names or [])

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
