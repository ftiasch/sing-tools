#!/usr/bin/env python
import argparse
import json
import logging
import os
from pathlib import Path

import argcomplete
import requests

from common import setup_logging
from lib import Parser

setup_logging()


def down(args):
    def fetch(dst, src):
        logging.info("Downloading %s" % (dst))
        try:
            content = requests.get(src).text
            with open(f"run/{dst}.txt", "w") as f:
                f.write(content)
        except:
            logging.exception("")

    fetch("okgg", "https://rss.okggrss.top/link/3tddh0FHKbzOdLoE?mu=2")
    fetch("ww", "https://ww5271.xyz/rss/mEWrAf3/D7jmP8?net_type=TROJAN")


def guess_region(name: str) -> str:
    config = {
        "US": ["US", "美国"],
        "HK": ["HongKong", "HK", "港", "🇭🇰"],
        "JP": ["Osaka", "JP", "日", "🇯🇵"],
        "SG": ["新加坡"],
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


def common_filter(prefix: str, name: str) -> list[list[str]]:
    region = guess_region(name)
    if region not in ("US", "HK", "JP", "SG", "TW", "TH", "PH"):
        return []
    tags = [["proxy", prefix]]
    if region in ("US", "JP", "SG", "TW"):
        tags.append(["openai"])
    return tags


def okgg_filter(name: str, _: dict):
    return common_filter("okgg", name)


def ww_filter(name: str, _: dict):
    if "游戏" in name:
        return []
    return common_filter("ww", name.split("·")[1])


def select(args) -> Parser:
    parser = Parser(args.nameserver, ipv6=args.ipv6)
    parser.parse("okgg", okgg_filter)
    parser.parse("ww", ww_filter)
    return parser


def gen(args):
    used_geosites = set()

    def geosite(site):
        g = f"geosite-{site}"
        used_geosites.add(g)
        return g

    prefix = Path(args.prefix)

    config = {
        "log": {"level": "error", "timestamp": True},
        "dns": {
            "servers": [
                {
                    "tag": "dns_direct",
                    "address": "tls://1.12.12.12",
                    "strategy": "ipv4_only",
                    "detour": "direct",
                },
                {"tag": "dns_success", "address": "rcode://success"},
                {"tag": "dns_refused", "address": "rcode://refused"},
                {"tag": "dns_fakeip", "address": "fakeip"},
            ],
            "rules": [
                {
                    "domain_suffix": [
                        ".archlinux.org",
                        ".bopufund.com",
                        "ftiasch.xyz",
                        ".limao.tech",
                        ".ntp.org",
                    ],
                    "server": "dns_direct",
                },
                {"outbound": "any", "server": "dns_direct"},
                {"query_type": ["A", "CNAME"], "server": "dns_fakeip"},
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
                "listen": "127.0.0.1",
                "listen_port": 5353,
                "network": "udp",
                "override_address": "1.0.0.1",
                "override_port": 53,
            },
            {
                "type": "direct",
                "tag": "direct-in",
                "listen": "::",
                "listen_port": 23378,
                "network": "tcp",
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
        "route": {
            "final": "proxy",
            "auto_detect_interface": True,
        },
        "experimental": {
            "cache_file": {"enabled": True, "path": "cache.db", "store_fakeip": True},
            "clash_api": {
                "external_controller": "0.0.0.0:9090",
                "external_ui": str(prefix / "yacd-meta"),
            },
        },
    }

    parser = select(args)
    config["outbounds"] = parser.assemble()

    rules = [
        {"inbound": "dns-in", "outbound": "dns-out"},
        {"inbound": "http-direct-in", "outbound": "direct"},
        {
            "type": "logical",
            "mode": "or",
            "rules": [
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
        },
        {
            "ip_cidr": ["13.115.121.128"],
        },
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

    # Application specified rules
    def app_rule(rs, outbound):
        rules.append(
            {
                "rule_set": geosite(rs),
                "outbound": outbound,
            }
        )

    # app_rule("github", "okgg")
    app_rule("openai", "openai")

    config["route"]["rules"] = rules

    rule_set = [
        {
            "type": "local",
            "tag": "geoip-cn",
            "format": "binary",
            "path": str(prefix / "sing-geoip" / "rule-set" / "geoip-cn.srs"),
        }
    ]
    for g in used_geosites:
        rule_set.append(
            {
                "type": "local",
                "tag": g,
                "format": "binary",
                "path": str(prefix / "sing-geosite" / "rule-set" / f"{g}.srs"),
            }
        )

    config["route"]["rule_set"] = rule_set
    with open("run/config.json", "w") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)


def list_str(values):
    return values.split(",")


def main():
    os.chdir(os.path.dirname(__file__) or ".")

    parser = argparse.ArgumentParser()
    argcomplete.autocomplete(parser)
    parser.add_argument(
        "func",
        choices=["gen", "down"],
        default="gen",
    )
    parser.add_argument("-p", "--prefix", default="/usr/share")
    parser.add_argument("-n", "--nameserver", default="223.5.5.5")
    parser.add_argument("--ipv6", default=False, action="store_true")
    args = parser.parse_args()
    globals().get(args.func)(args)


if __name__ == "__main__":
    main()
