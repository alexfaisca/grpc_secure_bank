#!/bin/bash

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <user|firewall|bank|database|authenticationServer>"
  exit 1
fi

service="$1"

echo "Installing dependencies..."
bash dependencies.sh

case "$action" in
  "user")
    echo "Initializing the user..."
    bash Scripts/initialize/user.sh
    ;;
  "firewall")
    echo "Initializing the firewall..."
    bash Scripts/initialize/firewall.sh
    ;;
  "bank")
    echo "Initializing the bank..."
    bash Scripts/initialize/bank.sh
    ;;
  "database")
    echo "Initializing the database..."
    bash Scripts/initialize/database.sh
    ;;
  "authenticationServer")
    echo "Initializing the authentication server..."
    bash Scripts/initialize/authenticationServer.sh
    ;;
  *)
    echo "Unknown action: $action"
    echo "Usage: $0 <user|firewall|bank|database|authenticationServer>"
    exit 1
    ;;
esac

exit 0
