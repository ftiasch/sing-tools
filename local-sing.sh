#!/bin/bash

# Function to change DNS settings
change_dns() {
	local dns_server=$1
	local direction=$2

	echo "Setting DNS to $dns_server ($direction)"

	# Get the active connection name
	CONNECTION=$(nmcli -t -f NAME connection show --active | head -n 1)

	if [ -z "$CONNECTION" ]; then
		echo "No active network connection found!"
		exit 1
	fi

	# Modify DNS settings
	nmcli connection modify "$CONNECTION" ipv4.dns "$dns_server"
	nmcli connection up "$CONNECTION"

	echo "DNS successfully set to $dns_server for connection: $CONNECTION"
}

# Check if argument is provided
if [ $# -eq 0 ]; then
	echo "Usage: $0 {up|down}"
	exit 1
fi

DIRECTION=$1

case $DIRECTION in
up)
	echo "Going up!"
	change_dns "127.0.0.1" "up"
	sudo systemctl --no-pager --full start sing-box
	if [ $? -eq 0 ]; then
		echo "✅ sing-box service started successfully"
	else
		echo "❌ Failed to start sing-box service"
		sudo systemctl --no-pager --full status sing-box
	fi
	;;
down)
	echo "Going down!"
	change_dns "223.5.5.5" "down"
	sudo systemctl --no-pager --full stop sing-box
	if [ $? -eq 0 ]; then
		echo "✅ sing-box service stopped successfully"
	else
		echo "❌ Failed to stop sing-box service"
		sudo systemctl --no-pager --full status sing-box
	fi
	;;
*)
	echo "Invalid argument: $DIRECTION"
	echo "Usage: $0 {up|down}"
	exit 1
	;;
esac
