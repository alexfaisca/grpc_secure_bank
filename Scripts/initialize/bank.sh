#! /bin/bash

set -x

firewallAddress="10.0.2.2"
firewallPort="8000"
bankAddress="192.168.0.2"
bankPort="22" 
databaseAddress="192.168.1.2"
databasePort="22"

sudo Scripts/flush_rules.sh

sudo ifconfig enp0s3 192.168.0.2/24 up
sudo ip route add default via 192.168.0.1
sudo /etc/init.d/network-manager force-reload