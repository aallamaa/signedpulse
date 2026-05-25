#!/bin/sh
# Example SignedPulse hook with port-knock LEASE support (nftables).
#
# The server runs this only AFTER a pulse is fully verified. With the lease
# config in examples/server.toml it is invoked two ways:
#
#   signedpulse-hook grant  <ip> <client_id> <new>     # on each verified pulse
#   signedpulse-hook revoke <ip> <client_id> <reason>  # when access is dropped
#
# "grant" opens access for <ip>; "revoke" closes it. <new> is "1" on a new or
# reactivated session (first pulse, or the first after the lease expired) and
# "0" on a keep-alive renewal — handy for logging/notifying only on new access.
# <reason> tells revoke why it fired: "expired" (the lease timed out) or "bye"
# (the client released it on shutdown).
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

action="${1:?usage: signedpulse-hook <grant|revoke> <ip> <client_id> [<new>|<reason>]}"
ip="${2:?missing ip}"
client_id="${3:-unknown}"
# 4th arg is {new} for grant, {reason} for revoke (the action selects meaning).
new="${4:-0}"
reason="${4:-expired}"

case "${action}" in
  grant)
    # Idempotent add: allow this verified IP through. `add element` is a no-op
    # if the element already exists, so running it every pulse is fine.
    nft add element inet filter signedpulse_allow "{ ${ip} }" 2>/dev/null || true
    [ "${new}" = "1" ] &&
      logger -t signedpulse-hook "granted ${ip} (client=${client_id}, new session)"
    ;;
  revoke)
    # Access dropped (lease expired, or the client sent a BYE). Close the pinhole.
    nft delete element inet filter signedpulse_allow "{ ${ip} }" 2>/dev/null || true
    logger -t signedpulse-hook "revoked ${ip} (client=${client_id}, reason=${reason})"
    ;;
  *)
    logger -t signedpulse-hook "unknown action: ${action}"
    exit 1
    ;;
esac
