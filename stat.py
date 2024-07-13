#!/usr/bin/env python

import asyncio
import json
from datetime import datetime, timezone

import dateutil.parser
import pandas as pd
import websockets

API_URI = "wss://sing.ftiasch.xyz/connections"


async def main():
    pd.set_option("display.max_rows", 500)
    rules = pd.read_csv("rules.csv")
    async with websockets.connect(API_URI) as wss:
        data = json.loads(await wss.recv())
        stat = []
        for conn in data["connections"]:
            chain = conn["chains"][-1]
            if chain in ("dns-out",):
                continue
            download = conn["download"]
            elapsed = (
                datetime.now(timezone.utc) - dateutil.parser.isoparse(conn["start"])
            ).total_seconds()
            download_rate = download / elapsed
            meta = conn["metadata"]
            if download > 0:
                host = meta["host"]
                matched = False
                if host:
                    for _, rule in rules.iterrows():
                        if host.endswith(rule["suffix"]):
                            matched = True
                            if chain != rule["chain"]:
                                print(
                                    f"WARN: {host} is route to {chain} instead of {rule['chain']}"
                                )
                if not matched:
                    stat.append(
                        {
                            "download": download,
                            "download_rate": download_rate,
                            "upload": conn["upload"],
                            "host": host,
                            "dport": meta["destinationPort"],
                            "dst_ip": meta["destinationIP"],
                            "chain": chain,
                            "rule": conn["rule"],
                        }
                    )
        stat = pd.DataFrame(stat)
        print(stat.sort_values("download", ascending=False))


if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
