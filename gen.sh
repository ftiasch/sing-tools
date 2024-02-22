#!/bin/bash
set -o errexit

cd "$(dirname "${BASH_SOURCE[0]}")"

. .env/bin/activate

if [[ "$1" == "down" ]]; then
	# echo "Downloading Cats-Team/AdRules"
	# curl https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules.list -o run/cats-team-adrules.list

	# echo "Downloading Loyalsoldier/v2ray-rules-dat"
	# if [[ ! -d run/v2ray-rules-dat ]]; then
	# 	git clone https://github.com/Loyalsoldier/v2ray-rules-dat.git run/v2ray-rules-dat -b release
	# fi
	# (cd run/v2ray-rules-dat && git pull)

	python cli.py down
fi

# for dat in run/v2ray-rules-dat/*.txt; do
# 	name=$(basename $dat .txt)
# 	echo $name
# 	python clash2sing.py <$dat >tmp
# 	sing-box rule-set compile tmp -o run/$name.srs
# 	rm -rf tmp
# done
#
# python surge2sing.py <run/cats-team-adrules.list >tmp
# sing-box rule-set compile tmp -o run/cats-team-adrules.srs
# rm -rf tmp

python cli.py gen
sing-box check -c run/config.json

sudo cp run/config.json /etc/sing-box/config.json
sudo systemctl restart sing-box
