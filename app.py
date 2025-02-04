import json

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

if __name__ == "__main__":
    app()
