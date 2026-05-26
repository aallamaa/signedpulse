#!/bin/sh
# Example SignedPulse hook with port-knock LEASE support (nftables).
#
# The server runs this only AFTER a pulse is fully verified. With the lease
# config in examples/server.toml it is invoked two ways:
#
#   signedpulse-hook grant  <ip> <client_id> <new>                 # each verified pulse
#   signedpulse-hook revoke <ip> <client_id> <reason> <ip_clients> # a client's lease ends
#
# "grant" opens access for <ip>; "revoke" is called PER CLIENT when its lease
# ends. <new> is "1" on a new or reactivated session, "0" on a keep-alive renewal
# — handy for logging/notifying only on new access. <reason> tells revoke why it
# fired: "expired" (the lease timed out) or "bye" (the client released it).
#
# <ip_clients> is the count of OTHER clients still holding access on the same
# source IP. The firewall set is keyed by IP, so we only DELETE the IP when this
# is 0 (we were the last client behind that NAT) — otherwise a sibling still
# needs the pinhole open.
#
# Both operations MUST be IDEMPOTENT: grant may run every pulse, and a server
# restart forgets in-memory leases, so a grant can recur and a revoke can be
# skipped until the client pulses again — design the rules to tolerate that.
#
# Arguments are passed as literal argv elements (never through a shell by the
# server), so they are safe to use directly.
#
# Install: sudo install -m 0755 examples/signedpulse-hook.sh /usr/local/sbin/signedpulse-hook
set -eu

action="${1:?usage: signedpulse-hook <grant|revoke> <ip> <client_id> [<new>|<reason> <ip_clients>]}"
ip="${2:?missing ip}"
client_id="${3:-unknown}"
# 4th arg is {new} for grant, {reason} for revoke (the action selects meaning);
# {ip_clients} (5th) is only passed on revoke.
new="${4:-0}"
reason="${4:-expired}"
ip_clients="${5:-0}"

case "${action}" in
  grant)
    # Idempotent add: allow this verified IP through. `add element` is a no-op
    # if the element already exists, so running it every pulse is fine.
    nft add element inet filter signedpulse_allow "{ ${ip} }" 2>/dev/null || true
    [ "${new}" = "1" ] &&
      logger -t signedpulse-hook "granted ${ip} (client=${client_id}, new session)"
    ;;
  revoke)
    # A client's lease ended. Only close the pinhole when no OTHER client is still
    # behind this IP (shared NAT) — otherwise leave it open for the sibling.
    if [ "${ip_clients}" = "0" ]; then
      nft delete element inet filter signedpulse_allow "{ ${ip} }" 2>/dev/null || true
      logger -t signedpulse-hook "revoked ${ip} (client=${client_id}, reason=${reason})"
    else
      logger -t signedpulse-hook "client ${client_id} left ${ip} (reason=${reason}); ${ip_clients} still active, keeping open"
    fi
    ;;
  *)
    logger -t signedpulse-hook "unknown action: ${action}"
    exit 1
    ;;
esac
