#!/bin/sh
# Example SignedPulse hook.
#
# The server runs this (via the argv in server.toml's [command]) only AFTER a
# pulse has been fully verified. It is invoked as:
#
#   signedpulse-hook <ip> <client_id> [<source_port>] [<param>]
#
# depending on the placeholders you put in `command.argv`. Arguments are passed
# as literal argv elements (never through a shell by the server), so they are
# safe to use directly.
#
# Install to the path referenced by server.toml, e.g.:
#   sudo install -m 0755 examples/signedpulse-hook.sh /usr/local/sbin/signedpulse-hook
set -eu

ip="${1:?usage: signedpulse-hook <ip> <client_id> [<source_port>] [<param>]}"
client_id="${2:-unknown}"
source_port="${3:-}"
param="${4:-}"

logger -t signedpulse-hook "verified pulse: client=${client_id} ip=${ip} port=${source_port} param=${param}"

# --- Port-knocking use case --------------------------------------------------
# SignedPulse makes a strong, replay-proof, encrypted port knock: only an
# authorized client can cause this hook to run, and it runs with the client's
# real (NAT'd) source IP. Open a firewall pinhole for that IP here.
#
# Example with nftables — allow this IP to reach SSH:
#   nft add element inet filter signedpulse_allow "{ ${ip} }"
#
# To let the CLIENT choose which port to open, configure its param_command to
# emit the port number and add "{param}" to the server's argv; then:
#   case "${param}" in
#     22|443|8443) nft add element inet filter "knock_${param}" "{ ${ip} }" ;;
#     *) logger -t signedpulse-hook "rejecting unexpected param: ${param}"; exit 1 ;;
#   esac
#
# (Always validate {param} against an allow-list before acting on it, as above.)
