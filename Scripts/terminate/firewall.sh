#!/bin/bash

# Revert all rules
sudo flush_rules.sh

# Disable IP forwarding
sudo sysctl net.ipv4.ip_forward=0

# Bring down the network interfaces
sudo ifconfig enp0s3 down
sudo ifconfig enp0s8 down

# Revert Allow forwarding of packets that are part of an already established connection
sudo iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -D INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT 

# Revert SSH rate limit
sudo iptables -D INPUT -p tcp --dport 8000 -m state --state NEW -m recent --set
sudo iptables -D INPUT -p tcp --dport 8000 -m state --state NEW -m recent --update --seconds 10 --hitcount 5 -j DROP

# Revert Redirect external connections to the bank
sudo iptables -t nat -D PREROUTING -i enp0s9 --dst 10.0.2.2 -p tcp --dport 8000 -j DNAT --to-destination 192.168.0.2:23

# Revert Bank -> Database
sudo iptables -D FORWARD -i enp0s3 -p tcp --sport 23: --dport 23 -m state --state NEW --source 192.168.0.2 -d 192.168.1.2 -j ACCEPT

sudo /etc/init.d/network-manager restart