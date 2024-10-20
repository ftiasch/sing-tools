import datetime
import json
import logging
import os
import shelve
import signal
import sys

import dateutil.parser
import pandas as pd
import typer
import websocket

DEFAULT_DB_PATH = "conn"

app = typer.Typer(pretty_exceptions_enable=False)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s|%(levelname)s|%(message)s",
)


class Store:
    def __init__(self, db_path: str):
        self.db = shelve.open(db_path, "c")

    def __del__(self):
        self.db.close()

    def process(self, data):
        for conn in data["connections"]:
            self.db[conn["id"]] = conn
        logging.info("len(db)=%d", len(self.db))


def get_base_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 2:
        parts = parts[-2:]
    return ".".join(parts)


is_running = True


@app.command()
def collect(api_url: str, *, db_path=DEFAULT_DB_PATH):
    def on_sigint(signum, frame):
        global is_running
        is_running = False
        ws.close()

    store = Store(db_path=db_path)
    signal.signal(signal.SIGINT, on_sigint)
    while is_running:
        ws = websocket.WebSocketApp(
            os.path.join(api_url, "connections"),
            on_message=lambda _, msg: store.process(json.loads(msg)),
        )
        ws.run_forever()


@app.command()
def summary(*, db_path=DEFAULT_DB_PATH, hours: int = 24):
    stat = []
    from_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        hours=hours
    )
    with shelve.open(db_path, "r") as db:
        for conn in db.values():
            metadata = conn["metadata"]
            if conn["rule"].endswith("direct-out"):
                continue
            if dateutil.parser.isoparse(conn["start"]) < from_start:
                continue
            host = metadata["host"]
            if host:
                base_domain = get_base_domain(host)
                if base_domain not in stat:
                    stat.append(
                        {
                            "base_domain": base_domain,
                            "rule": conn["rule"],
                            "download": conn["download"] / 1_000_000,
                            "upload": conn["upload"] / 1_000_000,
                        }
                    )
    stat = pd.DataFrame(stat)
    stat["sum"] = stat["download"] + stat["upload"]
    stat.groupby(["base_domain", "rule"]).sum().sort_values(
        "sum", ascending=False
    ).to_csv(sys.stdout)


@app.command()
def search(base_domain: str, *, db_path=DEFAULT_DB_PATH):
    result = []
    with shelve.open(db_path, "r") as db:
        for conn in db.values():
            metadata = conn["metadata"]
            host = metadata["host"]
            if host and get_base_domain(host) == base_domain:
                result.append(conn)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    app()
