#!/bin/bash
set -o errexit
cd "$(dirname "${BASH_SOURCE[0]}")"
. ../.env/bin/activate
if [[ "$1" == "down" ]]; then
	python cli.py down
fi
python cli.py gen
sudo sing-box merge /etc/sing-box/custom.json -c config.template.json -c run/config.json
for f in ad-block cn; do
	sudo sing-box rule-set compile -o /etc/sing-box/$f.srs run/$f.json
done
sudo systemctl restart sing-box@custom
