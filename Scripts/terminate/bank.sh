#! /bin/bash

sudo ip route del default via 192.168.0.1

sudo ifconfig enp0s3 down
sudo ifconfig enp0s3 0.0.0.0

sudo /etc/init.d/network-manager restart