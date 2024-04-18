#! /bin/bash

sudo ifconfig enp0s3 down
sudo ifconfig enp0s3 0.0.0.0

sudo ip route del default via 192.168.1.1

sudo /etc/init.d/network-manager restart