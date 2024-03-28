#!/bin/bash
set -o errexit

cd "$(dirname "${BASH_SOURCE[0]}")"

. .env/bin/activate

if [[ "$1" == "down" ]]; then
	shift
	python cli.py down
fi

python cli.py gw_gen $@
# sing-box check -c run/config.json

rsync run/config.json marf-gw:/etc/sing-box
rsync -arz /usr/share/sing-box/sing-geosite-rule-set/ marf-gw:/usr/share/sing-geosite/
for d in yacd-meta sing-geoip; do
	rsync -arz /usr/share/$d marf-gw:/usr/share
done
ssh marf-gw service sing-box restart
