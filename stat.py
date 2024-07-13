#!/usr/bin/env python

import asyncio
import json
from datetime import datetime, timezone

import dateutil.parser
import pandas as pd
import websockets

API_URI = "wss://sing.ftiasch.xyz/connections"


async def main():
    async with websockets.connect(API_URI) as wss:
        while True:
            data = json.loads(await wss.recv())
            stat = []
            for conn in data["connections"]:
                if conn["chains"][-1] != "PROXY":
                    continue
                download = conn["download"]
                elapsed = (
                    datetime.now(timezone.utc) - dateutil.parser.isoparse(conn["start"])
                ).total_seconds()
                download_rate = download / elapsed
                meta = conn["metadata"]
                stat.append(
                    {
                        "download": download,
                        "download_rate": download_rate,
                        "upload": conn["upload"],
                        "host": meta["host"],
                        "dport": meta["destinationPort"],
                        "dst_ip": meta["destinationIP"],
                        "rule": conn["rule"],
                    }
                )
            stat = pd.DataFrame(stat)
            print(stat.sort_values("download", ascending=False))


if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
