#!/bin/bash

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <user|firewall|bank|database|authenticationServer>"
  exit 1
fi

service="$1"

case "$action" in
  "user")
    echo "Terminating the user..."
    bash Scripts/terminate/user.sh
    ;;
  "firewall")
    echo "Terminating the firewall..."
    bash Scripts/terminate/firewall.sh
    ;;
  "bank")
    echo "Terminating the bank..."
    bash Scripts/terminate/bank.sh
    ;;
  "database")
    echo "Terminating the database..."
    bash Scripts/terminate/database.sh
    ;;
  "authenticationServer")
    echo "Terminating the authentication server..."
    bash Scripts/terminate/database.sh
    ;;
  *)
    echo "Unknown action: $action"
    echo "Usage: $0 <user|firewall|bank|database|authenticationServer>"
    exit 1
    ;;
esac

exit 0
