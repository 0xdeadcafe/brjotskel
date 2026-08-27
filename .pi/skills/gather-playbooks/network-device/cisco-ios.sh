#!/bin/sh
# gather/network-device/cisco-ios.sh — Cisco IOS/IOS-XE IR command reference
# Requires: Privileged exec mode (enable)
# Read-only: YES — show/display commands only
# Sensitive-output: YES — may print credential material or credential-bearing artifacts
# Footprint: Zero on device
# Purpose: Triage a Cisco IOS router/switch for active sessions, credential
#          exposure, lateral movement paths, and evidence of tampering.
#
# ⚠️  Network devices don't always support heredoc injection.
#     Paste command blocks directly into a remote_exec session or use
#     remote_exec one command at a time.
#
# Usage:
#   remote_connect(protocol="telnet", target="10.10.0.1:23", name="router01")
#   remote_connect(protocol="ssh",    target="admin@10.10.0.1",  name="router01")
#   # Then paste individual sections below

# --- IDENTITY & VERSION ---
# show version
# show inventory
# show clock detail

# --- ACTIVE SESSIONS (attacker presence) ---
# show users                        # who is logged in right now
# show line                         # line state — active TTY/VTY connections
# show tcp brief                    # active TCP sessions
# show ip nat translations          # NAT sessions — may reveal internal hosts
# show crypto session               # active VPN/IPsec sessions

# --- ROUTING (pivot paths) ---
# show ip route                     # full routing table
# show ip route summary             # summary — how many routes, protocols
# show ip bgp summary               # BGP neighbors — adjacent AS
# show ip ospf neighbor             # OSPF neighbors — internal topology
# show ip eigrp neighbors           # EIGRP peers
# show ip arp                       # ARP table — adjacent hosts

# --- INTERFACES ---
# show interfaces                   # full interface state with counters
# show ip interface brief           # quick interface/IP summary
# show interfaces trunk             # trunk ports (switches) — VLAN exposure

# --- ACCESS CONTROL (security posture) ---
# show access-lists                 # all ACLs and hit counts
# show ip access-lists              # IP ACLs only
# show run | section access-list    # ACL config in running config
# show run | section ip inspect     # CBAC/zone-based firewall rules
# show policy-map                   # QoS/policy-map — may reveal traffic shaping

# --- AAA & CREDENTIALS ---
# show aaa servers                  # configured RADIUS/TACACS servers
# show aaa sessions                 # active AAA sessions
# show run | include username       # local user accounts
# show run | include aaa            # AAA configuration
# show run | include tacacs         # TACACS+ config
# show run | include radius         # RADIUS config
# show run | include secret         # password hashes (type 5/7/9)

# --- SSH ---
# show ip ssh                       # SSH version, timeout, auth retries
# show ssh                          # active SSH sessions
# show run | include crypto key     # SSH key presence

# --- VPN / CRYPTO ---
# show crypto isakmp sa             # IKEv1 SA state — VPN peers
# show crypto ikev2 sa              # IKEv2 SA state
# show crypto ipsec sa              # IPsec SA details — encrypted tunnels
# show crypto map                   # crypto map configuration

# --- LOGGING ---
# show logging                      # syslog buffer (recent events)
# show logging | include SEC-LOGIN  # login events
# show logging | include CONFIG     # configuration change events
# show logging | include CRYPTO     # crypto/VPN events
# show logging | include line       # VTY line events (attacker session clues)

# --- RUNNING CONFIG (sensitive — full exposure) ---
# show running-config               # full current config including credentials
# show startup-config               # saved config (compare to running)
# show archive                      # config archive/rollback history

# --- INTEGRITY ---
# show platform integrity           # (IOS-XE 16.x+) secure boot verification
# verify /md5 flash:                # hash of flash filesystem
# dir flash:                        # flash contents — look for unexpected files

# --- INTEL RECORDING GUIDANCE ---
# Record discovered hosts from 'show ip arp' and 'show ip route':
#   intel_add(category="host", id="<hostname>",
#     data="ip: <ip>\nstatus: suspected\nsource:\n  host: router01\n  method: show ip arp\n  playbook: network-device/cisco-ios.sh",
#     summary="Host discovered via ARP on router01")
#
# Record VPN peers as pivot paths:
#   intel_add(category="pivot", id="vpn-to-<peer>",
#     data="target: <peer-id>\nchain:\n  - hop: router01\n    method: ipsec-vpn\nstatus: confirmed\nsource:\n  host: router01\n  method: show crypto isakmp sa",
#     summary="IPsec VPN tunnel to <peer> via router01")
