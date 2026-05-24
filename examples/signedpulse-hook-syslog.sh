#!/bin/sh
# Minimal SignedPulse hook: log the verified pulse to syslog and do nothing else.
#
# The server runs this (via server.toml's [command] argv) ONLY after a pulse has
# been fully verified. `logger` sends the line to the system log daemon, which
# writes it to /var/log/messages (RHEL/Fedora/SUSE) or /var/log/syslog
# (Debian/Ubuntu). Do not append to /var/log/messages directly: it is owned by
# the log daemon, is usually not writable by the hook's user, and bypasses
# rotation. `logger` is the correct, portable way to reach syslog.
#
# Configure the server to pass the placeholders you want logged, e.g.:
#   [command]
#   argv = ["/usr/local/sbin/signedpulse-hook",
#           "{ip}", "{client_id}", "{source_port}", "{param}"]
#
# Arguments are passed as literal argv elements (never through a shell by the
# server), so they are safe to use directly.
#
# Install:
#   sudo install -m 0755 examples/signedpulse-hook-syslog.sh /usr/local/sbin/signedpulse-hook
set -eu

ip="${1:?usage: signedpulse-hook <ip> [<client_id>] [<source_port>] [<param>]}"
client_id="${2:-unknown}"
source_port="${3:-}"
param="${4:-}"

# -t sets the syslog tag; the line lands in /var/log/messages via the log daemon.
logger -t signedpulse-hook \
  "verified pulse: client=${client_id} ip=${ip} port=${source_port} param=${param}"
