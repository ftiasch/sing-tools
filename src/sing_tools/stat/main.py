import datetime
import json
import shelve
import sys

import dateutil.parser
import pandas as pd
import typer


app = typer.Typer(pretty_exceptions_enable=False)


def get_base_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 2:
        parts = parts[-2:]
    return ".".join(parts)


@app.command()
def stat(*, db_path="conn", hours: int = 24):
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
def search(base_domain: str, *, db_path="conn"):
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
