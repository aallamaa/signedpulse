#!/usr/bin/python3
"""
SignedPulse hook (Python) — runs ONLY after a pulse is fully verified.

The server invokes this with whatever you put in server.toml's [command]. The
lease setup passes a grant action on every verified pulse and a revoke action
when a source IP stops pulsing:

    [command]
    argv        = ["/usr/local/sbin/signedpulse-hook", "grant",  "{ip}", "{client_id}", "{new}"]
    revoke_argv = ["/usr/local/sbin/signedpulse-hook", "revoke", "{ip}", "{client_id}", "{reason}"]

so this script receives, positionally:

    argv[1] action       "grant" (each verified pulse) or "revoke" (access dropped)
    argv[2] ip           the client's REAL source IP, from UDP packet metadata
    argv[3] client_id    the verified 64-hex client id
    argv[4] new/reason   grant: "1" on a new/reactivated session, "0" on a renewal;
                         revoke: why it fired — "expired" (lease timed out) or
                         "bye" (client released it on shutdown)

The placeholders ({ip} {client_id} {source_port} {param} {new}) are passed as
LITERAL argv elements — never through a shell — so they are safe to use directly.
If you shell out, keep using subprocess with an argument LIST (never shell=True).

Make both actions IDEMPOTENT: grant runs on every pulse, and because leases live
in the server's memory a restart forgets them (a grant may recur and a revoke
may be skipped until the client pulses again).

Exit status is recorded by the server and shown in `signedpulse-server status`
(`last hook` / `last revoke`): 0 = success, non-zero = failure (with the code).

Prerequisite: an nftables set your firewall rules consult, e.g.
    table inet filter {
        set signedpulse_allow { type ipv4_addr; }
        chain input { ... ip saddr @signedpulse_allow accept ... }
    }
The daemon runs the hook as its own user (root, for nft) with a scrubbed
environment whose PATH includes /usr/sbin, so `nft` resolves.

Install:  sudo install -m 0755 examples/signedpulse-hook.py /usr/local/sbin/signedpulse-hook
"""
import ipaddress
import subprocess
import sys
import syslog

# The nftables family + table holding the set, and the set name. This example
# manages an IPv4 set; for IPv6 add a parallel set and switch on ip.version.
TABLE = ("inet", "filter")
SET = "signedpulse_allow"


def run_nft(op: str, ip: ipaddress._BaseAddress) -> subprocess.CompletedProcess:
    """Run `nft <op> element <table> <set> { <ip> }` with literal args (no shell)."""
    return subprocess.run(
        ["nft", op, "element", *TABLE, SET, "{ %s }" % ip],
        capture_output=True,
        text=True,
        check=False,
    )


def benign(stderr: str, *needles: str) -> bool:
    """True if nft's error is the harmless idempotent case (already/doesn't exist)."""
    low = stderr.lower()
    return any(n in low for n in needles)


def main() -> int:
    syslog.openlog(ident="signedpulse-hook", facility=syslog.LOG_AUTH)
    args = sys.argv[1:]
    if len(args) < 3:
        syslog.syslog(syslog.LOG_ERR, "usage: <grant|revoke> <ip> <client_id> [<new>]; got %r" % args)
        return 2

    action, ip_str, client_id = args[0], args[1], args[2]
    # 4th arg is {new} for grant, {reason} for revoke (the action selects meaning).
    is_new = len(args) > 3 and args[3] == "1"
    reason = args[3] if len(args) > 3 else "expired"
    who = client_id[:12]  # the server already validated this is canonical hex

    # The server passes the kernel-observed source IP, but validate defensively
    # before handing it to the firewall.
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        syslog.syslog(syslog.LOG_ERR, "invalid ip %r (action=%s)" % (ip_str, action))
        return 2

    if action == "grant":
        # `add element` errors if the element already exists — treat that as
        # success so running on every pulse is idempotent.
        r = run_nft("add", ip)
        ok = r.returncode == 0 or benign(r.stderr, "already exists", "exists")
        if is_new:
            syslog.syslog(syslog.LOG_NOTICE, "granted %s client=%s… (new session)" % (ip, who))
        else:
            syslog.syslog(syslog.LOG_INFO, "renewed %s client=%s…" % (ip, who))
        if not ok:
            syslog.syslog(syslog.LOG_ERR, "nft add failed for %s: %s" % (ip, r.stderr.strip()))
            return r.returncode or 1
        return 0

    if action == "revoke":
        # `delete element` errors if it's already gone — treat that as success.
        r = run_nft("delete", ip)
        ok = r.returncode == 0 or benign(r.stderr, "does not exist", "no such")
        syslog.syslog(syslog.LOG_NOTICE, "revoked %s client=%s… (reason=%s)" % (ip, who, reason))
        if not ok:
            syslog.syslog(syslog.LOG_ERR, "nft delete failed for %s: %s" % (ip, r.stderr.strip()))
            return r.returncode or 1
        return 0

    syslog.syslog(syslog.LOG_ERR, "unknown action %r" % action)
    return 2


if __name__ == "__main__":
    sys.exit(main())
