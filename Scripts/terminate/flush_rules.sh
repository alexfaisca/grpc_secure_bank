#!/bin/bash

sudo iptables -F
sudo iptables -t nat -F
sudo iptables -P FORWARD DROP
sudo iptables -P INPUT DROP
sudo iptables -P PREROUTING DROP