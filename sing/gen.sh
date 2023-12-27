#!/bin/bash
set -o errexit
cd "$(dirname "${BASH_SOURCE[0]}")"
. ../.env/bin/activate
if [[ "$1" == "down" ]]; then
	python cli.py down
fi
sudo systemctl stop sing-box@custom
python cli.py gen
sudo sing-box merge /etc/sing-box/custom.json -c config.template.json -c run/config.json
sudo systemctl start sing-box@custom
