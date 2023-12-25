#!/bin/bash
set -o errexit

sudo systemctl stop sing-box@custom
./cli.py gen
sudo sing-box merge /etc/sing-box/custom.json -c config.template.json -c run/config.json
sudo systemctl start sing-box@custom
