import shelve
import typer
import pandas as pd
import sys
import json

app = typer.Typer(pretty_exceptions_enable=False)


def get_base_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 2:
        parts = parts[-2:]
    return ".".join(parts)


@app.command()
def stat(*, db_path="conn"):
    stat = {}
    with shelve.open(db_path, "r") as db:
        for conn in db.values():
            metadata = conn["metadata"]
            host = metadata["host"]
            if host:
                base_domain = get_base_domain(host)
                if base_domain not in stat:
                    stat[base_domain] = {
                        "base_domain": base_domain,
                        "download": 0,
                        "upload": 0,
                    }
                stat[base_domain]["download"] += conn["download"]
                stat[base_domain]["upload"] += conn["upload"]
    stat = pd.DataFrame(stat.values())
    stat["sum"] = stat["download"] + stat["upload"]
    stat.sort_values("sum", ascending=False, inplace=True)
    stat.to_csv(sys.stdout)


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
