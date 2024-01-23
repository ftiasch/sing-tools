#!/usr/bin/env python
import argparse
import json
import logging
import os
from pathlib import Path
from typing import Optional

import argcomplete
import requests

from common import setup_logging
from lib import Parser

setup_logging()


def down():
    def fetch(dst, src):
        with open(f"run/{dst}.txt", "w") as f:
            f.write(requests.get(src).text)

    fetch("okgg", "https://rss.okggrss.top/link/3tddh0FHKbzOdLoE?mu=2")
    fetch("ww", "https://ww5271.xyz/rss/mEWrAf3/D7jmP8?net_type=TROJAN")


def okgg_filter(name: str, _: dict) -> bool:
    for loc in ("日本", "新加坡", "HongKong"):
        if loc in name:
            return True
    return False


def ww_filter(name: str, _: dict) -> bool:
    for loc in ("HK", "JP", "TW"):
        if loc in name:
            return True
    return False


def select(nameserver: Optional[str] = None) -> Parser:
    parser = Parser(nameserver)
    parser.parse("okgg", okgg_filter)
    # parser.parse("ww", ww_filter)
    return parser


LOCAL_DNS = "223.5.5.5"


def gen():
    used_geosites = set()

    def geosite(site):
        g = f"geosite-{site}"
        used_geosites.add(g)
        return g

    used_local_rules = set()

    def local_rule(rule):
        used_local_rules.add(rule)
        return rule

    def adblock_rule():
        return geosite("category-ads-all")

    config = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {
                    "tag": "dns_proxy",
                    "address": "tls://8.8.8.8",
                    "strategy": "ipv4_only",
                    "detour": "proxy",
                },
                {
                    "tag": "dns_direct",
                    "address": LOCAL_DNS,
                    "strategy": "ipv4_only",
                    "detour": "direct",
                },
                {"tag": "dns_success", "address": "rcode://success"},
                {"tag": "dns_refused", "address": "rcode://refused"},
                {"tag": "dns_fakeip", "address": "fakeip"},
            ],
            "rules": [
                {
                    "domain_suffix": [".bopufund.com", ".ftiasch.xyz", ".limao.tech"],
                    "server": "dns_direct",
                },
                {"outbound": "any", "server": "dns_direct"},
                {
                    "rule_set": adblock_rule(),
                    "server": "dns_refused",
                    "disable_cache": True,
                },
                {"query_type": ["A"], "server": "dns_fakeip"},
                {
                    "query_type": "CNAME",
                    "rule_set": geosite("cn"),
                    "server": "dns_direct",
                },
                {
                    "type": "logical",
                    "mode": "and",
                    "rules": [
                        {"query_type": "CNAME"},
                        {"rule_set": geosite("cn"), "invert": True},
                    ],
                    "server": "dns_proxy",
                },
                {
                    "query_type": ["A", "CNAME"],
                    "invert": True,
                    "server": "dns_refused",
                    "disable_cache": True,
                },
            ],
            "fakeip": {
                "enabled": True,
                "inet4_range": "10.32.0.0/12",
            },
            "independent_cache": True,
        },
        "inbounds": [
            {
                "type": "direct",
                "tag": "dns-in",
                "listen": "::",
                "listen_port": 53,
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
        ],
        "route": {
            "final": "proxy",
            "auto_detect_interface": True,
        },
        "experimental": {
            "cache_file": {"enabled": True, "path": "cache.db", "store_fakeip": True},
            "clash_api": {
                "external_controller": "0.0.0.0:9090",
                "external_ui": "/usr/share/yacd",
            },
        },
    }

    parser = select(LOCAL_DNS)
    config["outbounds"] = parser.assemble()

    rules = [
        {"inbound": "dns-in", "outbound": "dns-out"},
        {
            "type": "logical",
            "mode": "or",
            "rules": [
                {"rule_set": adblock_rule()},
                {"network": "tcp", "port": 853},
                {"network": "udp", "port": 443},
                {"protocol": "stun"},
            ],
            "outbound": "block",
        },
    ]

    proxy_rules = [
        {
            "rule_set": geosite("google"),
        }
    ]
    for r in proxy_rules:
        rules.append(
            {
                **r,
                "outbound": "proxy",
            }
        )

    direct_rules = [
        {"ip_is_private": True},
        {"rule_set": "geoip-cn"},
        {
            "domain_suffix": [
                ".arpa",
                ".roborock.com",
                ".steamserver.net",
                ".syncthing.net",
            ]
        },
    ]
    # list subset first
    for rs in ("apple", "steam@cn", "cn"):
        direct_rules.append(
            {
                "rule_set": geosite(rs),
            }
        )
    for r in direct_rules:
        rules.append(
            {
                **r,
                "outbound": "direct",
            }
        )

    config["route"]["rules"] = rules

    rule_set = [
        {
            "type": "local",
            "tag": "geoip-cn",
            "format": "binary",
            "path": "/usr/share/sing-geoip/rule-set/geoip-cn.srs",
        }
    ]
    for g in used_geosites:
        rule_set.append(
            {
                "type": "local",
                "tag": g,
                "format": "binary",
                "path": f"/usr/share/sing-geosite/rule-set/{g}.srs",
            }
        )
    for r in used_local_rules:
        rule_set.append(
            {
                "type": "local",
                "tag": r,
                "format": "binary",
                "path": str(Path(os.getcwd()) / "run" / f"{r}.srs"),
            }
        )
    config["route"]["rule_set"] = rule_set
    with open("run/config.json", "w") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)


def test():
    parser = select()
    print(
        json.dumps([o["tag"] for o in parser.outbounds], ensure_ascii=False, indent=2)
    )


def main():
    os.chdir(os.path.dirname(__file__) or ".")

    parser = argparse.ArgumentParser()
    argcomplete.autocomplete(parser)
    parser.add_argument(
        "func",
        choices=["gen", "test", "down"],
        default="gen_dry_run",
    )
    args = parser.parse_args()
    globals().get(args.func)()


if __name__ == "__main__":
    main()
