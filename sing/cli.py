#!/usr/bin/env python
import os
import argparse
import logging
from typing import Optional
import requests
import argcomplete
import json

from lib import Parser, gen_rules


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)1.1s%(asctime)s.%(msecs)03d %(process)d %(filename)s:%(lineno)d] %(message)s",
    datefmt="%Y%m%d %H:%M:%S",
)


def down():
    def fetch(dst, src):
        with open(f"run/{dst}.txt", "w") as f:
            f.write(requests.get(src).text)

    fetch("okgg", "https://rss.okggrss.top/link/3tddh0FHKbzOdLoE?mu=2")
    fetch("ww", "https://ww5271.xyz/rss/mEWrAf3/D7jmP8?net_type=TROJAN")


def okgg_filter(name: str, _: dict) -> bool:
    if "AI" in name:
        return True
    return False


def ww_filter(name: str, __: dict) -> bool:
    if "JP" in name:
        return True
    return False


def select(nameserver: Optional[str] = None) -> Parser:
    parser = Parser(nameserver)
    parser.parse("okgg", okgg_filter)
    # parser.parse("ww", ww_filter)
    return parser


def gen():
    used_geosites = set()

    def geosite(site):
        g = f"geosite-{site}"
        used_geosites.add(g)
        return g

    local_dns = "223.5.5.5"
    config = {
        "log": {"level": "error", "timestamp": True},
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
                    "address": local_dns,
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
                    "rule_set": geosite("category-ads-all"),
                    "server": "dns_refused",
                    "disable_cache": True,
                },
                {"query_type": ["A", "AAAA"], "server": "dns_fakeip"},
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
                    "query_type": ["A", "AAAA", "CNAME"],
                    "invert": True,
                    "server": "dns_refused",
                    "disable_cache": True,
                },
            ],
            "fakeip": {
                "enabled": True,
                "inet4_range": "198.18.0.0/15",
                "inet6_range": "fc00::/18",
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
                "inet6_address": "fdfe:dcba:9876::1/126",
                "auto_route": True,
                "strict_route": True,
                "stack": "system",
                "sniff": True,
            },
            {"type": "http", "tag": "http-in", "listen": "::", "listen_port": 8001},
        ],
        "route": {
            "rules": [
                {"inbound": "dns-in", "outbound": "dns-out"},
                {
                    "type": "logical",
                    "mode": "or",
                    "rules": [
                        {"rule_set": geosite("category-ads-all")},
                        {"network": "tcp", "port": 853},
                        {"network": "udp", "port": 443},
                        {"protocol": "stun"},
                    ],
                    "outbound": "block",
                },
                {
                    "type": "logical",
                    "mode": "or",
                    "rules": [
                        {"ip_is_private": True, "outbound": "direct"},
                        {"rule_set": "geoip-cn"},
                        {"rule_set": geosite("cn")},
                        {"rule_set": geosite("apple")},
                        {"rule_set": geosite("steam@cn")},
                        {
                            "domain_suffix": [
                                ".arpa",
                                ".roborock.com",
                                ".steamserver.net",
                                ".syncthing.net",
                            ]
                        },
                    ],
                    "outbound": "direct",
                },
            ],
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

    parser = select(local_dns)
    config["outbounds"] = parser.assemble()

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
