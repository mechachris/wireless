#!/bin/bash

# Wireless card for AP 
WIRELESS_INTERFACE=wlan0

# Interface to route traffic out
# For responder set VM NIC to "Host-Only"
# For DNS overrides set VM NIC to bridge through to internet
OUT_INTERFACE=eth0

# Assign IP to wireless interface
ifconfig $WIRELESS_INTERFACE 10.0.0.1/24 up

# Fire up DNS and DHCP server
dnsmasq -d -C dnsmasq.conf -H dns_entries

# Set IPtables rules for routing
sysctl -w net.ipv4.ip_forward=1
iptables -P FORWARD ACCEPT
iptables --table nat -A POSTROUTING -o $OUT_INTERFACE -j MASQUERADE

# Launch AP
hostapd ./hostapd.conf
