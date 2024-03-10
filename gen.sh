#!/bin/bash
set -o errexit

cd "$(dirname "${BASH_SOURCE[0]}")"

. .env/bin/activate

if [[ "$1" == "down" ]]; then
	shift
	python cli.py down
fi

python cli.py gen $@
sing-box check -c run/config.json

sudo cp run/config.json /etc/sing-box/config.json
sudo systemctl restart sing-box

# rsync -arPz /usr/share/yacd root@192.168.1.1:/root/sing/
# rsync -arPz /usr/share/sing-geoip root@192.168.1.1:/root/sing/
# rsync -arPz /usr/share/sing-geosite root@192.168.1.1:/root/sing/
