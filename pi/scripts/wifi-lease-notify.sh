#!/bin/sh
# dnsmasq DHCP lease callback — posts lease events to the portal.
#
# dnsmasq calls this script with:
#   $1 = action (add, old, del)
#   $2 = MAC address
#   $3 = IP address
#   $4 = hostname (may be empty)
#
# Installed as dhcp-script in dnsmasq.conf.

ACTION="$1"
MAC="$2"
IP="$3"
HOSTNAME="${4:-}"

PORTAL_URL="http://127.0.0.1:8080/api/wifi/lease_event"

PAYLOAD="{\"action\":\"${ACTION}\",\"mac\":\"${MAC}\",\"ip\":\"${IP}\",\"hostname\":\"${HOSTNAME}\"}"

# Fire-and-forget POST to portal (timeout 2s, ignore errors). Fork villa-2 (S6-01):
# the API token goes in a header read from stdin (printf is a shell builtin), so it
# never shows on a command line.
TOKEN_FILE=/etc/rfc2217/api-token
TOKEN=$(cat "$TOKEN_FILE" 2>/dev/null || true)
printf 'X-Harness-Token: %s\n' "$TOKEN" | \
curl -s -X POST -H "Content-Type: application/json" -H @- \
     -d "$PAYLOAD" --max-time 2 "$PORTAL_URL" >/dev/null 2>&1 || true
