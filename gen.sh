#!/bin/bash
set -o errexit

cd "$(dirname "${BASH_SOURCE[0]}")"

. .env/bin/activate

python cli.py $@
# sing-box check -c run/config.json

rsync run/config.json marf-gw:/etc/sing-box
# rsync -arz /usr/share/sing-box/sing-geosite-rule-set/ marf-gw:/usr/share/sing-geosite/
# rsync -arz /usr/share/sing-box/sing-geoip-rule-set/ marf-gw:/usr/share/sing-geoip/
# rsync -arz /usr/share/yacd-meta/ marf-gw:/usr/share/yacd-meta/
ssh marf-gw service sing-box restart

prefix=/home/ftiasch/Sync/sing
sed 's@/usr/share@.@g' run/config.json >$prefix/config.json
# rsync -arz /usr/share/sing-box/sing-geosite-rule-set/ $prefix/sing-geosite/
# rsync -arz /usr/share/sing-box/sing-geoip-rule-set/ $prefix/sing-geoip/
# rsync -arz /usr/share/yacd-meta/ $prefix/yacd-meta/
