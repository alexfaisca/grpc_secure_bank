#!/bin/bash

set -x

firewallAddress="10.0.2.2"
firewallPort="8000"
bankAddress="192.168.0.2"
bankPort="22" 
databaseAddress="192.168.1.2"
databasePort="22"

# Configure adapters
sudo ip addr add 192.168.0.1/24 dev enp0s3
sudo ip link set dev enp0s3 up

sudo ip addr add 192.168.1.1/24 dev enp0s8
sudo ip link set dev enp0s8 up

# Allow the system to act as router
sudo sysctl net.ipv4.ip_forward=1

# Reload the Network Manager service
sudo /etc/init.d/network-manager force-reload

# Flush all existing rules
sudo ./flush_rules.sh

# Allow forwarding of packets that are part of an already established connection
sudo iptables -I FORWARD  -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT 

# SSH rate limit
sudo iptables -A INPUT -p tcp --dport 8000 -m state --state NEW -m recent --set
sudo iptables -A INPUT -p tcp --dport 8000 -m state --state NEW -m recent --update --seconds 10 --hitcount 5 -j DROP

# Redirect external connections to the bank
sudo iptables -t nat -A PREROUTING -i enp0s9 --dst 10.0.2.2 -p tcp --dport 8000 -j DNAT --to-destination 192.168.0.2:23

# Bank -> Database (Careful)
sudo iptables -A FORWARD -i enp0s3 -p tcp --sport 23: --dport 23 -m state --state NEW --source 192.168.0.2 -d 192.168.1.2 -j ACCEPT
