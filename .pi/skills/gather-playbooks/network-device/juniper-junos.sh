#!/bin/sh
# gather/network-device/juniper-junos.sh — Juniper JunOS IR command reference
# Requires: Read-only or admin login
# Read-only: YES
# Sensitive-output: YES — may print credential material or credential-bearing artifacts
# Purpose: Triage a Juniper SRX/MX/EX device for active sessions, routing
#          topology, security policies, VPN state, and credential exposure.
#
# Usage:
#   remote_connect(protocol="ssh", target="admin@10.10.0.3", name="srx01")
#   # Paste command sections below
#
# Note: JunOS uses operational mode commands (no 'show' prefix required after
#       entering 'cli' / operational mode). Most commands below assume
#       operational mode.

# --- IDENTITY & VERSION ---
# show version                      # software version, model, serial
# show system uptime                # uptime and last reboot reason
# show chassis hardware             # hardware inventory

# --- ACTIVE SESSIONS ---
# show system users                 # currently logged-in users
# show system login                 # login configuration (accounts, classes)
# show security flow session        # active firewall sessions (SRX)
# show security flow session summary # session count by protocol

# --- ROUTING (pivot paths) ---
# show route                        # full routing table (inet.0)
# show route summary                # routing table summary
# show ospf neighbor                # OSPF neighbors
# show bgp summary                  # BGP peer state
# show isis adjacency               # IS-IS adjacencies
# show arp                          # ARP table — adjacent hosts
# show ldp neighbor                 # MPLS LDP neighbors

# --- INTERFACES ---
# show interfaces terse             # quick interface/IP summary
# show interfaces detail            # full interface stats
# show lldp neighbors               # LLDP neighbor discovery
# show ethernet-switching table     # MAC address table (EX switches)

# --- SECURITY POLICY (SRX) ---
# show security policies            # zone-based security policies
# show security zones               # zone definitions and interfaces
# show security nat source summary  # source NAT summary
# show security nat destination summary # destination NAT
# show security ike security-associations # IKE/VPN phase 1
# show security ipsec security-associations # IPsec SA state

# --- AAA & CREDENTIALS ---
# show configuration system login   # local user accounts with auth info
# show configuration system radius-server  # RADIUS config
# show configuration system tacplus-server # TACACS+ config
# show configuration | match secret | match password  # credential material

# --- SSH ---
# show configuration system services ssh  # SSH service config
# show system connections           # active connections (includes SSH)

# --- LOGGING ---
# show log messages | last 200      # syslog (last 200 lines)
# show log interactive-commands     # command history of interactive sessions
# show log dcd                      # interface/routing daemon log
# show log chassisd                 # chassis daemon log
# show security log                 # security log (SRX)

# --- RUNNING CONFIG ---
# show configuration                # full running configuration
# show configuration | display set  # config in set format (easier to grep)
# show configuration | match "secret|password|key"  # credential material

# --- INTEGRITY ---
# request system software verify    # verify software signatures (if supported)
# show system storage               # storage — look for unexpected files
# file list /var/tmp/               # temp files — staging area check

# --- INTEL RECORDING GUIDANCE ---
# BGP/OSPF/LLDP neighbors → pivot paths:
#   intel_add(category="host", id="<peer-id>",
#     data="ip: <peer-ip>\nhostname: <peer-id>\nplatform: network-device\nstatus: suspected\nsource:\n  host: srx01\n  method: show bgp summary",
#     summary="BGP peer <peer-id> discovered on srx01")
#
# IPsec SA → pivot path:
#   intel_add(category="pivot", id="vpn-to-<remote>",
#     data="target: <remote-id>\nchain:\n  - hop: srx01\n    method: ipsec-vpn\nstatus: confirmed\nsource:\n  host: srx01\n  method: show security ipsec security-associations",
#     summary="IPsec tunnel to <remote> confirmed via srx01")
