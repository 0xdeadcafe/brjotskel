#!/bin/sh
# gather/network-device/cisco-nxos.sh — Cisco NX-OS IR command reference
# Requires: Privileged exec (admin or network-admin role)
# Read-only: YES
# Purpose: Triage a Cisco Nexus switch for active sessions, VLAN exposure,
#          routing topology, AAA config, and evidence of tampering.
#
# Usage:
#   remote_connect(protocol="ssh", target="admin@10.10.0.2", name="nexus01")
#   # Paste command sections below

# --- IDENTITY & VERSION ---
# show version
# show module                       # line cards / modules
# show clock detail

# --- ACTIVE SESSIONS ---
# show users                        # logged-in users
# show login failures               # failed login attempts (NX-OS 7.x+)
# show system internal telnet connections  # telnet sessions if enabled

# --- VLAN / FABRIC ---
# show vlan brief                   # VLAN database — which VLANs exist
# show vlan                         # full VLAN state
# show interface trunk              # trunk ports and allowed VLANs
# show vpc                          # vPC domain state (dual-homed fabric)
# show fabric forwarding summary    # FabricPath (if enabled)

# --- ROUTING ---
# show ip route vrf all             # routing table across all VRFs
# show ip route summary             # counts by protocol
# show ip ospf neighbor             # OSPF peers
# show ip bgp summary               # BGP neighbors
# show ip arp vrf all               # ARP across all VRFs

# --- INTERFACES ---
# show interface brief              # all interfaces with status
# show ip interface brief           # L3 interfaces
# show cdp neighbors detail         # CDP — directly connected Cisco devices (topology)
# show lldp neighbors detail        # LLDP — vendor-agnostic neighbor discovery

# --- AAA & CREDENTIALS ---
# show aaa authentication           # AAA config
# show aaa servers                  # configured RADIUS/TACACS servers
# show run | include username       # local user accounts
# show run | include tacacs         # TACACS+ config
# show run | include radius         # RADIUS config
# show run | include password       # passwords (type 0/3/5/7)
# show role                         # defined user roles and permissions

# --- SSH ---
# show ssh server                   # SSH server state and version
# show ssh session                  # active SSH sessions

# --- LOGGING ---
# show logging                      # current log buffer
# show logging logfile              # persistent log file
# show logging | include LOGIN      # login events
# show accounting log               # AAA accounting log (command history)

# --- RUNNING CONFIG ---
# show running-config               # full current config
# show startup-config               # saved startup config

# --- INTEGRITY ---
# show version | include image      # software image name and version
# show system internal image-info   # image signature info
# dir bootflash:                    # flash contents

# --- INTEL RECORDING GUIDANCE ---
# CDP/LLDP neighbors → suspected hosts:
#   intel_add(category="host", id="<device-id>",
#     data="ip: <mgmt-ip>\nhostname: <device-id>\nplatform: network-device\nstatus: suspected\nsource:\n  host: nexus01\n  method: show cdp neighbors detail",
#     summary="Adjacent device discovered via CDP on nexus01")
