#!/usr/bin/env python
import os
import argparse
import logging
from typing import Optional
import requests
import argcomplete
import json

from lib import Parser


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
    parser = select("223.5.5.5")
    with open("run/config.json", "w") as f:
        json.dump(parser.assemble(), f, ensure_ascii=False, indent=2)


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
