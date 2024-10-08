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
                                    f"WARN: {host} is route to {chain} instead of {rule['chain']}: suffix={rule['suffix']}"
                                )
                            break
                if not matched:
                    stat.append(
                        {
                            "download_MB": download / 1024 / 1024,
                            "download_rate (KB/s)": download_rate / 1024,
                            "upload": conn["upload"],
                            "host": host,
                            "dport": meta["destinationPort"],
                            "dst_ip": meta["destinationIP"],
                            "chain": chain,
                            "rule": conn["rule"],
                        }
                    )
        stat = pd.DataFrame(stat)
        for g, df in stat.groupby("chain"):
            print(g)
            print(df.sort_values("download_MB", ascending=False))


if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
