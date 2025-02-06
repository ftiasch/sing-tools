import base64
import json
from urllib.parse import parse_qs, urlparse

import paramiko
import typer
import yaml


class FileUtils:
    @staticmethod
    def _load_yaml_file(file_path):
        with open(file_path, "r") as f:
            return yaml.safe_load(f)

    @staticmethod
    def _load_db(config):
        try:
            with open(config["db-path"], "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    @staticmethod
    def _save_db(config, db):
        with open(config["db-path"], "w") as f:
            json.dump(db, f)

# https://github.com/arminmokri/v2ray2json/blob/main/v2ray2json.py
class Convertor:
    name: str
    data: str

    def __init__(self, name, data):
        self.name = name
        self.data = data

    @staticmethod
    def b64decode(b):
        while len(b) % 4 != 0:
            b += "="
        return base64.urlsafe_b64decode(b).decode("utf-8")

    @staticmethod
    def parse_url(parsed_url):
        uuid, _rest = parsed_url.netloc.split("@", 1)
        host, _port = _rest.split(":", 1)
        return (uuid, host, int(_port))

    @staticmethod
    def convert_vless(config):
        parsed_url = urlparse(config)

        uuid, hostname, port = Convertor.parse_url(parsed_url)

        netquery = dict(
            (k, v if len(v) > 1 else v[0])
            for k, v in parse_qs(parsed_url.query).items()
        )

        typer.echo(name)

        # outbound = get_outbound_vless()

        # streamSetting = outbound.streamSettings
        # fingerprint = (
        #     netquery.get("fp")
        #     if "fp" in netquery
        #     else streamSetting.tlsSettings.fingerprint
        #     if streamSetting.tlsSettings
        #     else None
        # )

        # vnext = outbound.settings.vnext[0]
        # vnext.address = hostname
        # vnext.port = port

        # user = vnext.users[0]
        # user.id = uid
        # user.encryption = netquery.get("encryption", "none")
        # user.flow = netquery.get("flow", "")

        # sni = streamSetting.populateTransportSettings(
        #     transport=netquery.get("type", "tcp"),
        #     headerType=netquery.get("headerType", None),
        #     host=netquery.get("host", None),
        #     path=netquery.get("path", None),
        #     seed=netquery.get("seed", None),
        #     quicSecurity=netquery.get("quicSecurity", None),
        #     key=netquery.get("key", None),
        #     mode=netquery.get("mode", None),
        #     serviceName=netquery.get("serviceName", None),
        # )
        # streamSetting.populateTlsSettings(
        #     streamSecurity=netquery.get("security", ""),
        #     allowInsecure=allowInsecure,
        #     sni=sni if netquery.get("sni", None) == None else netquery.get("sni", None),
        #     fingerprint=fingerprint,
        #     alpns=netquery.get("alpn", None),
        #     publicKey=netquery.get("pbk", ""),
        #     shortId=netquery.get("sid", ""),
        #     spiderX=netquery.get("spx", ""),
        # )

    def convert(self):
        try:
            decoded_data = self.b64decode(self.data)
        except ValueError as e:
            typer.echo(f"Error: {e}", err=True)
            return []
        outbounds = []
        for config in decoded_data.splitlines():
            try:
                protocol, _ = config.split("://", maxsplit=1)
                match protocol:
                    case "ss":
                        outbounds.append(self.convert_ss(config))
                    case "vless":
                        outbounds.append(self.convert_vless(config))
                    case _:
                        typer.echo(f"Unsupported protocol: {protocol}", err=True)
            except Exception as e:
                typer.echo(f"Error: {e}", err=True)
        return outbounds

app = typer.Typer()


@app.command()
def download():
    config = FileUtils._load_yaml_file("config.yaml")
    db = FileUtils._load_db(config)
    if "providers" not in db:
        db["providers"] = {}
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.connect(config["paramiko"]["host"])
    try:
        for name, url in config["providers"].items():
            _, stdout, _ = ssh.exec_command(f"curl -m {config['timeout']} '{url}'")
            stdout = stdout.read().decode("utf-8")
            if stdout:
                db["providers"][name] = db["providers"].get(name, []) + [stdout]
                typer.echo(f"Provider {name} downloaded")
            else:
                typer.echo(f"Provider {name} is not available", err=True)
    finally:
        ssh.close()
        FileUtils._save_db(config, db)

@app.command()
def test():
    config = FileUtils._load_yaml_file("config.yaml")
    db = FileUtils._load_db(config)
    for name, data in db["providers"].items():
        convertor = Convertor(name, data[-1])
        typer.echo(convertor.convert())
        break


if __name__ == "__main__":
    app()
