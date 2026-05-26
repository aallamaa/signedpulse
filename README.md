# SignedPulse

SignedPulse lets a server **learn and verify the real UDP source IP of a client
that lives behind NAT or on a dynamic IP**, then run a configured hook command
with that IP as an argument. The exchange is authenticated with **Ed25519
signatures** over a **non-replayable challenge/response** protocol, framed in a
**compact binary format** and (by default) **fully encrypted** so a network
sniffer learns nothing — not even the protocol or the client id.

A typical use: a roaming machine periodically "pulses" your server; the server
verifies the pulse really came from that machine and updates a firewall
allow-list, a DNS record, or a port-knock rule with the freshly observed IP.

## Purpose

* The client is behind NAT / has a dynamic IP and cannot reliably know its own
  public address.
* The server *can* see the public source IP of any UDP datagram it receives.
* SignedPulse proves the datagram genuinely came from an authorized client
  (not a spoofer, not a replay) before trusting that observed IP and acting on
  it.

## Use as a port-knocking tool

SignedPulse is a strong, modern port knock. A classic port knock is a fixed,
sniffable, replayable sequence; SignedPulse instead requires an **Ed25519
signature** over a **single-use server nonce**, optionally inside a **fully
encrypted** datagram — so the knock cannot be observed, replayed, or forged, and
the server learns the client's real source IP from packet metadata. Point the
hook at your firewall to open a pinhole for that IP:

```toml
# server.toml
[command]
argv = ["/usr/local/sbin/signedpulse-hook", "grant", "{ip}", "{client_id}", "{new}"]
```

```sh
# signedpulse-hook (nftables): $1 is the action (grant|revoke), $2 the verified IP
case "$1" in
  grant)  nft add    element inet filter signedpulse_allow "{ $2 }" ;;
  revoke) nft delete element inet filter signedpulse_allow "{ $2 }" ;;
esac
```

(See `examples/signedpulse-hook.sh` for the full grant/revoke hook, and
"Access while pulsing" below for the matching `revoke_argv` config.) The client
can even choose *which* port to open by emitting it from
`param_command` and passing `{param}` to the hook (validate it against an
allow-list — see `examples/signedpulse-hook.sh`).

### Access while pulsing (leases)

Rather than leaving the pinhole open forever, let SignedPulse close it for you.
Set a **revoke hook** and the server tracks a *lease* **per client**: each
verified pulse runs the grant hook (`command.argv`) and renews that client's
lease; when a client stops pulsing, the server runs `command.revoke_argv` to
close it.

```toml
# server.toml
[command]
argv        = ["/usr/local/sbin/signedpulse-hook", "grant",  "{ip}", "{client_id}", "{new}"]
revoke_argv = ["/usr/local/sbin/signedpulse-hook", "revoke", "{ip}", "{client_id}", "{reason}", "{ip_clients}"]
```

The lease TTL is **derived from the client's own pulse interval**, which it
advertises in each RESPONSE: `TTL = interval × lease_grace_multiplier`
(default 3 → revoke after ~3 missed pulses), capped by `lease_max_seconds`. So a
client that keeps pulsing stays allowed; one that goes away is revoked
automatically — no separate timer or reconciler needed.

The grant hook also gets a `{new}` flag: `1` on a **new or reactivated** session
(first pulse, or the first after the lease expired) and `0` on a keep-alive
renewal — so you can log/notify only when access is freshly granted.

The revoke hook gets a `{reason}` placeholder so it can tell *why* it ran:
`expired` (the lease timed out — the client went silent) or `bye` (the client
released it explicitly on shutdown — see below). The grant hook receives
`reason=grant`. Use it to branch, e.g. `revoke … "{reason}"` then in the hook
`case "$reason" in bye) … ;; expired) … ;; esac`.

**Shared NAT.** Everything keys on the authenticated **`client_id`** — leases,
cooldown, `{new}`, per-client status, and the hooks all fire **per client**,
independently. The revoke hook **always runs** when a client's lease ends; the
server hands it `{ip_clients}` — the number of *other* clients still holding a
live lease on the **same source IP**. The hook decides what that means: for a
firewall that filters by IP, close the pinhole **only when `{ip_clients}` is 0**
(you were the last client behind that NAT) — a still-pulsing sibling keeps it
open. The firewall is just one consumer; another hook might log, page, or update
a per-client record regardless of the count.

```toml
revoke_argv = ["/usr/local/sbin/signedpulse-hook", "revoke", "{ip}", "{client_id}", "{reason}", "{ip_clients}"]
```

Make both hooks **idempotent**: the grant runs on every pulse (and, behind a
shared NAT, once per client → repeated `nft add` of the same IP), and because
leases live in memory a server restart forgets them (a grant may recur and a
revoke may be skipped until the client pulses again). See
`examples/signedpulse-hook.sh` for a complete grant/revoke nftables hook.

#### Clean shutdown (BYE)

When the client daemon stops gracefully (SIGTERM / Ctrl-C), it sends a signed
**BYE** to each server, which **releases the lease immediately** — the revoke
hook runs right away instead of after the grace period. A BYE is a full
`HELLO → CHALLENGE → BYE` exchange (same single-use nonce and anti-replay as a
pulse) signed over a *distinct* payload, so a captured RESPONSE can never be
re-framed into a release. It is on by default; set `bye_on_shutdown = false` in
`[client]` to disable. A BYE can also carry an optional `param` (sealed/signed
like a pulse's) passed to the revoke hook. Old servers that don't understand
BYE simply drop it and the lease times out as before.

You can also release on demand without stopping the daemon:

```sh
signedpulse-client bye                 # release the lease on every server
signedpulse-client bye --param drain   # … and pass {param} to the revoke hook
```

### One-shot pulse / ping / bye

Besides the long-running daemon (no subcommand), the client has one-shot
commands that run a single handshake against every configured server and exit
with a non-zero code if any fails (handy for cron/scripts):

| Command | Retries? | Effect |
| --- | --- | --- |
| `signedpulse-client pulse` | no (one attempt) | renew the lease once |
| `signedpulse-client ping`  | yes (SIP backoff) | renew the lease, retrying |
| `signedpulse-client bye`   | no | release the lease (signed BYE) |

`pulse` and `ping` send the configured `param_command` output as usual, or you
can override it for a single run with `--param <value>` (sealed and signed like
the configured param, subject to the same `param_max_len`):

```sh
signedpulse-client pulse --param deploy-v2
```

## Threat model

**What SignedPulse defends against**

* **Spoofed / unauthorized clients** — both the HELLO and the RESPONSE are
  Ed25519-signed, so only a holder of a configured client private key can elicit
  a CHALLENGE or produce a valid RESPONSE.
* **Replay** — a captured RESPONSE cannot be reused: each response is tied to a
  single-use, short-lived nonce bound to the requesting client_id and exact UDP
  source IP/port, with the signature covering that nonce plus protocol metadata.
  A captured HELLO cannot be reused either: it is bound to a timestamp (checked
  against a skew window) and a fresh nonce kept in a short-lived replay cache.
  (See "Replay protection" below.)
* **Command injection via client-controlled data** — the hook is run from an
  `argv` array with safe placeholder substitution; no shell is involved unless
  you explicitly opt in.
* **Eavesdropping (optional, on by default)** — with `wire_encryption`, every
  datagram is an opaque sealed blob (anonymous X25519 + XChaCha20-Poly1305 to the
  server's key); the client id, nonces, packet type and the optional parameter
  are all hidden. The optional parameter is always encrypted even with
  `wire_encryption` off.
* **Server impersonation (encrypted mode)** — the CHALLENGE is sealed with the
  server's *static* X25519 key, so a client only accepts a CHALLENGE that an
  on-path attacker cannot forge without the server's secret. (In cleartext mode
  the CHALLENGE is unauthenticated; the client still cannot be made to reveal its
  parameter, which is sealed to the server's key regardless.)
* **Unauthenticated floods / CPU exhaustion** — HELLO packets are rate-limited
  per source IP, packet size is bounded, concurrent executions are capped, and a
  source IP that sends more than `max_faulty_packets` malformed/undecryptable
  packets is **blacklisted** (dropped before any decryption work).

**What it does *not* do**

* With `wire_encryption = off`, packets are compact binary cleartext (still
  signed); an observer can then see the client id and nonces (but not the
  parameter, which stays sealed). The default `required` mode hides everything.
* It does not defend against an attacker who has stolen a client's private key.
* UDP source IPs *can* be spoofed on networks without ingress filtering, but a
  blind spoofer cannot complete the handshake: the CHALLENGE is sent to the
  claimed source address, so the attacker would also need to receive it.

## Protocol flow

```
   Client                                   Server
     |                                         |
     |  HELLO {client_id, ts, hello_nonce,     |
     |         signature}                      |
     |---------------------------------------->|  record source IP/port (from socket)
     |                                         |  (decrypt sealed datagram if enabled)
     |                                         |  rate-limit per source IP
     |                                         |  verify HELLO signature (authorize)
     |                                         |  check ts within skew window
     |                                         |  reject if (client_id, hello_nonce)
     |                                         |    already seen (replay)
     |                                         |  mint 256-bit single-use nonce,
     |                                         |  bind to (client_id, ip, port, ttl)
     |  CHALLENGE {client_id, nonce, expires}  |
     |<----------------------------------------|
     |                                         |
  build canonical payload, sign with Ed25519   |
  (optionally generate + seal a parameter)     |
     |  RESPONSE {client_id, nonce, [param],   |
     |            signature}                   |
     |---------------------------------------->|  verify: client known? nonce valid,
     |                                         |  unexpired, unused, same client,
     |                                         |  same source IP/port? signature ok?
     |                                         |  -> consume nonce (single-use)
     |                                         |  -> decrypt param, run argv with
     |                                         |     source IP from packet metadata
```

Both the HELLO and the RESPONSE are signed. Each uses a **canonical signing
payload** built by one shared function used by both peers, so the bytes that get
signed can never drift — the signature is computed over *this text*, never over
the wire bytes. `client_id` is hex; `nonce`/`param` are base64. `server_id` is
**not** transmitted; both sides use their configured value, so a client aimed at
the wrong server simply fails verification.

RESPONSE payload (`param` is the base64 *ciphertext*, or empty — encrypt-then-sign):

```
signedpulse:v2:response
server_id=<server_id>
client_id=<client_id_hex>
nonce=<base64_nonce>
interval=<advertised_pulse_interval_seconds>
expires_at=<expires_at_unix>
param=<base64_ciphertext_or_empty>
```

The `interval` is the client's own pulse cadence, advertised so the server knows
when to expect the next pulse (it drives the access lease — see "Access while
pulsing"). It is signed, so an on-path attacker cannot alter it.

A **BYE** (clean-shutdown lease release — see "Access while pulsing") uses the
same fields but a distinct header, so a captured RESPONSE signature can never be
replayed as a release (and vice versa):

```
signedpulse:v2:bye
server_id=<server_id>
client_id=<client_id_hex>
nonce=<base64_nonce>
interval=<advertised_pulse_interval_seconds>
expires_at=<expires_at_unix>
param=<base64_ciphertext_or_empty>
```

HELLO payload (signed with a fresh per-HELLO nonce and a timestamp):

```
signedpulse:v2:hello
server_id=<server_id>
client_id=<client_id_hex>
timestamp=<client_timestamp_unix>
hello_nonce=<base64_nonce>
```

### Wire format & encryption

Packets use a compact hand-rolled **binary** framing. In cleartext form a packet
is `header(2) || body`, where the 16-bit header packs a magic byte, a 4-bit
version and a 4-bit packet type; `client_id` is a 256-bit (32-byte) value. A
HELLO is ~122 bytes on the wire.

> **Wire compatibility.** The current protocol version is **v2** (the RESPONSE
> carries the client's advertised `interval`). It is **not** compatible with v1:
> a v1 packet is rejected (and silently dropped). Upgrade the server and all
> clients together.

With `wire_encryption` (default `required`), the datagram on the wire is instead
a **bare opaque sealed blob** — no header, no magic — so the protocol is
unfingerprintable and a sniffer sees only random-looking bytes. Encryption is an
anonymous X25519 sealed box (ephemeral X25519 + ECDH + HKDF-SHA256 →
XChaCha20-Poly1305) to the **server's X25519 key**, with the AEAD bound to a
per-use context string (`wire`/`param`/`reply`) so a ciphertext from one context
cannot be opened in another. The server seals the **CHALLENGE** back using its
*static* secret keyed to the client's transport-ephemeral key (a static-ephemeral
ECDH): since only the holder of the server's secret can produce a reply the
client accepts, this **authenticates the server to the client** — yet still needs
no per-client keys. The inner plaintext is the same signed binary packet, so
authentication/replay protection are unchanged.

### HELLO authentication and freshness

The HELLO is the first packet, so the server has no prior nonce to bind it to.
Instead, the client signs the HELLO over its own timestamp and a fresh random
`hello_nonce`. On receipt the server:

1. verifies the signature against the configured public key — so it only ever
   replies to **authorized, key-holding clients**, not to anyone who merely
   knows a (non-secret) `client_id`;
2. rejects the HELLO if its timestamp is outside `hello_max_skew_seconds`
   (default 30s) of the server clock; and
3. rejects it if `(client_id, hello_nonce)` was already seen — blocking
   **replays** of a captured HELLO.

Because each HELLO (including legitimate retries) carries a new random nonce, a
genuine retry is always distinct, while a third party replaying captured HELLO
bytes collides in the replay cache and is dropped. This requires **loose clock
synchronization (NTP)** between client and server. The replay cache is in-memory
and bounded by the skew window; it is cleared on server restart (see Security
notes).

## Replay protection

A previously captured **HELLO** cannot be replayed because it is signed over a
timestamp (rejected outside the skew window) and a fresh nonce that the server
remembers for the duration of that window — a resent HELLO collides with the
cached nonce and is dropped.

A previously captured **RESPONSE** cannot be replayed because the nonce it
carries:

* is **single-use** — consumed atomically on first valid use, then rejected as a
  replay for the remainder of its lifetime;
* **expires quickly** (`nonce_ttl_seconds`, default 30s);
* is **bound to the client_id** that requested it;
* is **bound to the UDP source IP/port** that requested it; and
* is **covered by the signature** along with the protocol metadata, so it cannot
  be lifted into a different message.

## Invisible to network probes

The server is designed to give a scanner **nothing**. It emits exactly one kind
of outbound packet — a CHALLENGE — and only in response to a HELLO that has
passed *every* check: rate limit, known `client_id`, valid Ed25519 signature,
in-window timestamp, and not-already-seen nonce. There is precisely one `send`
call in the whole server, and it sits at the end of that pipeline.

Everything else is dropped with **no reply at all**:

* random/garbage bytes, or (in encrypted mode) anything that fails to decrypt;
* a malformed binary packet (bad magic/version/type/length);
* a HELLO for an unknown `client_id`;
* a HELLO with an invalid signature;
* a HELLO with a stale/out-of-window timestamp;
* a replayed HELLO (seen nonce);
* a stray CHALLENGE or RESPONSE sent to the server unprompted.

The RESPONSE handler is not even given the socket, so it is *structurally*
incapable of replying — it can only run the hook or drop. As a result the server
does not confirm its own existence, the protocol it speaks, or whether a given
`client_id` is configured. A port scan or a malformed-packet probe sees silence.
This is enforced by the `server_is_silent_to_probes` integration test, which
fires a battery of bad inputs and asserts zero datagrams come back.

**Bounding decryption cost.** Because each datagram in encrypted mode triggers a
decryption attempt, a flood of fake packets could otherwise burn CPU. A source
IP that sends more than `max_faulty_packets` (default 10) packets that **fail to
decrypt or decode** is **blacklisted** for `blacklist_seconds`, and blacklisted
IPs are dropped *before* any decryption — checked first in the receive path. Only
those cheap-to-detect failures count; rate-limited, post-decrypt, or
authentication failures do **not** feed the blacklist, so a chatty or
misconfigured (or shared-NAT) legitimate client cannot blacklist itself. The
blacklisting is logged once, then further packets from that IP are dropped
silently until the block expires.

Caveat: the blacklist is keyed on the UDP source address, which is spoofable on
networks without ingress filtering — an attacker who can forge a victim's source
IP could get that IP blocked. Pair it with network-level anti-spoofing where that
matters, or set `max_faulty_packets = 0` to disable it.

**Attack lockdown.** If more than `attack_blacklist_threshold` distinct IPs are
blacklisted within `attack_window_seconds` (i.e. a broad flood is underway), the
server enters **lockdown**: it only processes datagrams from source IPs that
recently completed a handshake (an authenticated HELLO or verified pulse, kept
for `active_ip_ttl_seconds`), dropping all other sources *before* any decryption.
Already-active clients keep working; new/idle clients are turned away until the
flood subsides. Lockdown is self-clearing — it lifts automatically once the
blacklisting events age out of the window — and is logged once on entry. Set
`attack_blacklist_threshold = 0` to disable it.

Independently, the server caps the number of datagrams processed concurrently
(`max_inflight_packets`, default 1024 — excess is dropped while at capacity) and
the number of distinct blacklist-tracked IPs (`max_tracked_ips`, default
100000). Together these bound CPU, task, and memory growth even under a
distributed flood that never trips any single IP's blacklist.

**A note on timing.** Internally, an unknown `client_id` is rejected a touch
earlier than a known client with a bad signature (the latter spends time
verifying). Because the server never replies, a *remote* attacker has no
round-trip to measure and therefore cannot observe that difference — there is no
timing oracle over the network. It would only be measurable by an attacker
already running code on the same host (CPU/cache side channels), which is a far
stronger threat model than the network scanner this design targets and is out of
scope.

## Project layout

```
signedpulse/
  Cargo.toml                         # workspace
  examples/server.toml               # example server config
  examples/client.toml               # example client config
  crates/
    signedpulse-common/              # protocol, crypto, config (no async/net)
      src/protocol.rs                # packets + canonical signing payloads
      src/crypto.rs                  # Ed25519, nonce generation
      src/config.rs                  # TOML config structs
      src/service.rs                 # systemd/launchd unit rendering + install
      src/status.rs                  # on-demand status snapshot + PID/signal helpers
    signedpulse-server/
      src/server.rs                  # UDP loop, decryption, verification pipeline
      src/nonce_store.rs             # in-memory, single-use nonce store
      src/seen_cache.rs              # HELLO replay cache
      src/command_runner.rs          # CommandExecutor trait + process runner
      src/rate_limit.rs              # HELLO rate limit, cooldown, IP blacklist
    signedpulse-client/
      src/client.rs                  # handshake + periodic run loop
  xtask/                             # `cargo deploy` (build + install)
```

## Installation & setup

The `signedpulse` crate ships **both** binaries (`signedpulse-server` and
`signedpulse-client`), so a single command installs them to `~/.cargo/bin`:

```sh
cargo install signedpulse                                   # from crates.io (once published)
cargo install --git https://github.com/aallamaa/signedpulse signedpulse   # from Git
cargo install --path crates/signedpulse                     # from a local checkout
```

For a system-wide install (default prefix `/usr/local`), use `cargo deploy`,
which builds `--release` and installs both binaries:

```sh
sudo cargo deploy                 # installs to /usr/local/bin
cargo deploy --prefix ~/.local    # user install, no sudo
cargo deploy --uninstall          # remove them
```

(`cargo deploy` is a workspace alias for the bundled `xtask`.)

The whole setup is three commands once the binaries are in place.

### 1. On the server

```sh
# Write a starter config (defaults: bind 0.0.0.0:7370, server_id signedpulse-main,
# hook /usr/local/sbin/signedpulse-hook). Generates the server X25519 encryption
# key and prints its public half for clients.
sudo signedpulse-server init

# Install + start as a systemd service (auto-runs daemon-reload + enable --now).
sudo signedpulse-server install-service
```

`init` prints the exact line to run on each client, including the
`--server-key <PUBLIC>` value. It also fills in `--server <HOST>` for you: if you
bound to a concrete address it uses that, otherwise it auto-detects this host's
IP from the default route (the source address the kernel would use for outbound
traffic). On a NAT'd box that is the private IP, so replace it with the
public/reachable address if clients reach you differently. Edit
`/etc/signedpulse/server.toml` to point `command.argv` at your hook program.

### 2. On the client

Point the client at the server and give it the server's encryption public key
(from step 1). The client generates its own 256-bit id + signing keypair and
prints exactly what to run on the server:

```sh
# --server takes "HOST" (port defaults to 7370) or "HOST:PORT".
sudo signedpulse-client init --server 203.0.113.10 \
    --server-key "ZCWT…=" --label laptop-1
```

This writes `/etc/signedpulse/client.toml` (mode `0600`, since it holds the
private key) and prints something like:

```
=== Do this on the SERVER to authorize this client ===

Run:
  signedpulse-server add-client --client-id "9819…f8" --public-key "p3y91Ee…=" --label "laptop-1"
```

(Pass `--no-encryption` to both `init`s for a cleartext-binary setup that needs
no encryption key.)

### 3. Authorize the client on the server

Copy the printed command and run it on the **server**:

```sh
sudo signedpulse-server add-client --client-id "9819…f8" --public-key "p3y91Ee…=" --label laptop-1
sudo systemctl restart signedpulse-server   # pick up the new client
```

`add-client` validates the id (64 hex) and public key, refuses duplicates, and
appends a `[[clients]]` block to the server config.

### 4. Start the client as a service

```sh
# Linux (system service):
sudo signedpulse-client install-service
# Linux (per-user service):
signedpulse-client install-service --user
# macOS (installs a launchd LaunchAgent in ~/Library/LaunchAgents):
signedpulse-client install-service
```

`install-service` auto-detects the platform (systemd on Linux, launchd on
macOS), writes the unit/plist referencing the running binary and `--config`
path, and tries to activate it. If it cannot (e.g. not run with privileges), it
prints the exact commands to run. Use `--print` to preview the unit without
writing anything.

### Checking status

Both binaries have a `status` subcommand that shows what a running daemon is
doing:

```sh
signedpulse-server status
signedpulse-client status
```

Example output (the terminal view is colorized — green for healthy, red for
errors, yellow for warnings; color is auto-disabled when piped or when
`NO_COLOR` is set):

```
$ signedpulse-server status
SignedPulse server
  service      active (running) [systemctl]
  config       /etc/signedpulse/server.toml
               bind 0.0.0.0:7370 · server_id signedpulse-main · clients 3
  pid          4821 · uptime 2h13m

Activity
  last pulse    203.0.113.7:51456 · 2m ago
  last hook     grant "laptop-1" → 203.0.113.7 · exit 0 · 2m ago
  last revoke   bye "phone-2" → 198.51.100.9 · exit 0 · 40s ago

Counters
  hello 144 · verified 140 · rejected 4 · replays 0 · leases 3

Clients (3)
  laptop-1
    pulse    203.0.113.7:51456 · 2m ago
    hook     grant · exit 0 · 2m ago
  phone-2
    pulse    198.51.100.9:33012 · 5m ago
    revoke   bye · exit 0 · 40s ago

Leases (revoked when the countdown elapses with no new pulse)
  203.0.113.7          laptop-1         revoke in 12m43s

$ signedpulse-client status
SignedPulse client
  service      active (running) [systemctl]
  config       /etc/signedpulse/client.toml
               client_id 9819…f8 · server 203.0.113.10:7370
  pid          5120 · uptime 1h02m

Servers (1)
  main (203.0.113.10:7370)
    last pulse   OK · 43s ago
    next pulse   in ~4m17s
    last result  ok
```

For scripting, `status --json` prints the raw live snapshot instead of the
human view (or `null` when the daemon isn't running):

```
$ signedpulse-server status --json | jq .verified
140
```

**How it works (and why it's safe).** `status` is **local-only** — it never
sends anything over the network, so it does not weaken the "invisible to probes"
property. The daemon keeps its live counters in memory and writes them to a
state file **only on demand**: `status` reads the daemon's PID file, sends it
`SIGUSR1`, the daemon writes a fresh snapshot, and `status` reads it back. There
are no periodic disk writes and no admin port.

The snapshot and PID files default to `$XDG_RUNTIME_DIR/signedpulse/` (falling
back to `/run/signedpulse/`), are created mode `0600`, and are cleared on reboot.
For a per-user systemd service or a macOS launchd agent — where `/run` is not
user-writable — set `state_file` in the config to a writable path; both the
daemon and `status` honour it. Service up/down comes best-effort from
`systemctl`/`launchctl`; if neither is available it shows `unknown` (the live
data still works as long as the daemon is running and can write its state file).

### Manual / ad-hoc running

```sh
signedpulse-server --config /etc/signedpulse/server.toml
signedpulse-client --config /etc/signedpulse/client.toml
```

Logging verbosity is controlled with `RUST_LOG`, e.g. `RUST_LOG=debug`.

### One-shot pulse / ping (no daemon)

Instead of running the client as a service you can fire a single handshake and
exit — handy for cron, scripts, or testing connectivity:

```sh
signedpulse-client pulse    # one HELLO→CHALLENGE→RESPONSE per server, NO retry
signedpulse-client ping     # same, but retries (SIP backoff) if no reply
```

Both run one cycle against every configured server (the `[client]` primary and
each `[client.servers.*]`), print a per-server `ok` / `FAILED` line, and exit
non-zero if any server did not respond — so they compose with shell `&&` and
cron alerting. `pulse` makes exactly one attempt (waiting `retry_initial_ms` for
the reply); `ping` makes up to `retries` attempts with the configured backoff
(`retry_initial_ms` → ×2 each retry, capped at `retry_max_ms`). (A daemonized client keeps the access lease alive; a periodic `pulse`
from cron does too, as long as it runs more often than the lease TTL.)

### Generating a keypair by hand

`signedpulse-client init` generates keys for you. If you want a bare keypair
(e.g. to manage configs yourself):

```sh
signedpulse-client generate-key
```

This prints a base64 **private key** (for the client config) and a base64
**public key** (for the server config). The private key never leaves the client.

## Configuration

### Server (`server.toml`)

```toml
[server]
bind = "0.0.0.0:7370"
server_id = "signedpulse-main"
nonce_ttl_seconds = 30
command_timeout_seconds = 10
client_cooldown_seconds = 60     # default 0 = disabled; 60 shown as an example
max_packet_size = 2048
hello_rate_max = 30              # HELLOs per source IP per window (0 disables)
hello_rate_window_seconds = 60
hello_max_skew_seconds = 30      # accepted clock skew for signed HELLO timestamps
max_faulty_packets = 10          # blacklist a source IP after this many bad packets
blacklist_seconds = 300
attack_blacklist_threshold = 10  # lockdown if > this many IPs blacklisted in the window
attack_window_seconds = 10
attack_rejection_threshold = 256 # ...or > this many rejected packets in the window
active_ip_ttl_seconds = 900      # how long a handshaked IP stays lockdown-allowlisted
max_inflight_packets = 1024      # concurrent datagrams processed (0 = unbounded)
max_tracked_ips = 100000         # cap on per-IP tracking maps (0 = unbounded)
wire_encryption = "required"     # or "off" for cleartext binary
encryption_private_key = "BASE64_X25519_SECRET"   # generated by `init`
max_param_len = 256
lease_grace_multiplier = 3       # lease TTL = client interval × this (revoke after ~3 misses)
lease_max_seconds = 86400        # cap on a derived lease TTL

[command]
# Placeholders (literal args, no shell): {ip} {client_id} {source_port} {param} {new} {reason} {ip_clients}
#   {new}        = "1" on a new/reactivated session, "0" on a keep-alive renewal
#   {reason}     = "grant" | "expired" (lease timed out) | "bye" (client released it)
#   {ip_clients} = count of OTHER clients still on this source IP (0 = last one;
#                  on a revoke, only close an IP-based firewall rule when it's 0)
argv = ["/usr/local/sbin/signedpulse-hook", "grant", "{ip}", "{client_id}", "{new}"]
# Optional per-client revoke (runs on every lease end / BYE; omit to leave open):
revoke_argv = ["/usr/local/sbin/signedpulse-hook", "revoke", "{ip}", "{client_id}", "{reason}", "{ip_clients}"]
working_dir = "/"
max_concurrent = 4
allow_shell = false              # DANGEROUS if true; keep false

[[clients]]
client_id = "9819…f8"            # 64 hex chars (256-bit)
public_key = "BASE64_ED25519_PUBLIC_KEY"
label = "laptop-1"               # optional, for logs/status
```

### Client (`client.toml`)

```toml
[client]
client_id = "9819…f8"            # 64 hex chars (256-bit)
server_addr = "203.0.113.10:7370"
server_id = "signedpulse-main"
interval_seconds = 300
private_key = "BASE64_ED25519_PRIVATE_KEY"
retry_initial_ms = 500           # SIP backoff: attempt k waits min(500·2^(k-1), retry_max_ms)
retry_max_ms = 4000              # backoff cap
retries = 3
wire_encryption = true                       # must match the server
server_encryption_key = "BASE64_X25519_SERVER_PUBLIC"
# Optional: stdout of this command is sealed + signed and passed to the hook as {param}
# param_command = ["/usr/local/bin/get-tag"]
# param_command_timeout_seconds = 5
# param_max_len = 256
```

### Pulsing multiple servers

One client can pulse several servers at once. `[client]` is the primary server;
add a `[client.servers.<name>]` table for each additional one. The table key is a
**local label** (used for status and uniqueness), *not* the wire `server_id`.

Each server signs its payloads with a `server_id` that **must match that remote
server's configured `server_id`** — otherwise every HELLO is rejected as an
invalid signature. That `server_id` defaults to the label, so you only set it
explicitly when they differ (e.g. two servers that both kept the default
`signedpulse-main`). Every target reuses the shared identity (`client_id` /
`private_key`) but runs its own independent pulse loop, inherits any omitted field
from `[client]`, and has its **own** X25519 key (`server_encryption_key` is never
inherited).

It is fine for two servers to share a `server_id`: in the default encrypted mode
each pulse is sealed to that server's *own* X25519 key, so a datagram for one
server cannot even be decrypted (let alone replayed) by another. If you run with
`wire_encryption = "off"`, that per-server key separation is gone, so give each
server a **distinct `server_id`** to keep a cleartext HELLO from being replayable
across servers.

```toml
[client]
client_id = "9819…f8"
server_addr = "203.0.113.10:7370"
server_id = "signedpulse-main"
private_key = "BASE64_ED25519_PRIVATE_KEY"
server_encryption_key = "BASE64_X25519_MAIN_PUBLIC"
interval_seconds = 300

[client.servers.backup]                 # "backup" is just a local label
server_addr = "203.0.113.20:7370"
server_id = "signedpulse-main"          # set this to the REMOTE server's server_id
server_encryption_key = "BASE64_X25519_BACKUP_PUBLIC"
interval_seconds = 600                  # optional; else inherits [client]
```

Rather than editing the file by hand, add a server (same address flags as `init`).
`--server-id` is the remote's server_id (omit if it equals `--name`); `--interval`
is optional, and `--no-encryption` switches that server to cleartext:

```sh
sudo signedpulse-client add-server --name backup --server 203.0.113.20 \
    --server-key "BASE64_X25519_BACKUP_PUBLIC" \
    --server-id signedpulse-main \
    --interval 600
```

It validates the inputs, rejects a duplicate or primary-colliding label, appends
the `[client.servers.<name>]` block, rewrites the config atomically at `0600`, and
prints the exact `signedpulse-server add-client …` line (with this client's public
key) to run on the new server.

Authorize the **same** client public key on each server (or use separate client
identities/configs if you prefer per-server key isolation), then restart the
client. `signedpulse-client status` reports each server separately by label.

### Passing a client-generated parameter

If `param_command` is set, the client runs it each pulse, takes its stdout
(trimmed, length-capped by `param_max_len`, control-chars rejected), **encrypts**
it to the server's X25519 key, and includes it in the RESPONSE. The signature
covers the *ciphertext* (encrypt-then-sign), so it is confidential on the wire
and tamper-proof. The server decrypts it and passes the plaintext to the hook
wherever you placed `{param}` in `command.argv` — as a single literal argument
(no shell). It always fits one UDP packet; a too-long value is rejected.

## Security notes

* **The source IP is taken from the UDP packet metadata, never from the packet
  body.** A client could put any IP in a packet field; that value is attacker
  controlled and meaningless. The whole point of the system is to learn the
  *observed* source address — the address the kernel reports for the datagram —
  which is exactly what the hook receives. Trusting a body field would let a
  client (or a spoofer) make the server act on an arbitrary IP.
* **No shell by default.** The hook runs via `tokio::process::Command` with an
  argv array, so a hostile value is passed as one literal argument and is never
  parsed as shell syntax. The hook also runs with a **scrubbed environment**
  (`env_clear()` plus a fixed minimal `PATH`), so `LD_PRELOAD`/`IFS`/`BASH_ENV`
  and the like cannot influence it. The hook receives the **canonical 64-hex
  `client_id`** (the verified identity, not the operator label). The
  client-supplied `{param}` is attacker-influenced text: it is rejected if it
  contains control characters or begins with `-`, but still place it so it cannot
  be read as an *option* by your hook (prefer `KEY={param}` / a trailing
  positional after `--`, and validate against an allow-list) — see
  `examples/signedpulse-hook.sh`.
* **`allow_shell` means remote code execution — keep it `false`.** Setting
  `allow_shell = true` re-enables `sh -c` and joins the substituted argv into one
  shell string. The client-supplied `{param}` then becomes **shell code**, so any
  authorized (or compromised) client can run arbitrary commands as the daemon's
  user. The leading-`-` guard does not help here. Only enable it in fully trusted,
  controlled setups, and never with `{param}`/`{ip}` in the argv.
* **The hook runs as the daemon's user.** The verified-pulse hook is a child of
  the server process and inherits its uid. Binding the default port (7370 > 1024)
  does **not** require root, so prefer running the server under a **dedicated
  unprivileged account** and granting only what the hook needs (e.g.
  `CAP_NET_ADMIN` for a firewall hook) rather than running everything as root.
  The generated systemd unit sets `NoNewPrivileges=true`; you can tighten it
  further with directives such as `User=`, `ProtectSystem=strict`, and
  `PrivateTmp=true` — but a firewall/port-knock hook typically needs `AF_NETLINK`
  and write access, so add sandboxing deliberately and test the hook still works.
* **Silent to probes.** The server emits exactly one kind of reply — a
  CHALLENGE — and only in response to a fully validated, non-replayable HELLO.
  Every other input (malformed bytes, wrong protocol/version, unknown client,
  bad signature, stale or replayed HELLO, stray CHALLENGE/RESPONSE) is dropped
  with no response at all, so the server does not reveal itself to scanners.
  This is covered by the `server_is_silent_to_probes` integration test.
* **Secrets are never logged.** Private keys, signatures, and full nonces are
  kept out of logs; failures log a short, specific reason instead.
* **Encrypted by default.** `wire_encryption = "required"` makes every datagram
  an opaque sealed blob, so the client id, nonces, packet type and parameter are
  hidden and the protocol is unfingerprintable. The optional parameter is sealed
  to the server's X25519 key regardless of this setting (encrypt-then-sign). In
  this mode the CHALLENGE is **server-authenticated** (sealed with the server's
  static key to the client's transport ephemeral) and **bound to the client's
  HELLO nonce** via the AEAD additional-data, so a captured CHALLENGE cannot be
  replayed back into the client against a different HELLO. In `wire_encryption =
  "off"` mode the CHALLENGE is cleartext and unauthenticated to the client — only
  use `off` on a trusted network, or where the server's reply does not need to be
  trusted (the server-side guarantees still hold either way).
* **Bounded resources.** Maximum packet size, HELLO rate limiting, command
  timeout, max concurrent executions, and per-client/per-IP cooldown all guard
  against abuse and runaway hooks. A source IP that sends more than
  `max_faulty_packets` malformed/undecryptable packets is blacklisted (checked
  before any decryption), bounding CPU-flood attacks. The blacklist, per-IP HELLO
  rate limiter, and lockdown active-IP allow-list are all hard-capped at
  `max_tracked_ips` distinct IPs; the nonce store and HELLO replay cache are
  bounded by their TTL and only grow via signature-authenticated HELLOs, so a
  pure source-spoofer cannot inflate them.
* **UDP source spoofing has inherent limits — know what each defense does.** On a
  network without ingress filtering an attacker can forge source IPs. Because the
  per-IP HELLO rate limiter and the per-IP blacklist are keyed on the (spoofable)
  source address, a flood that rotates source IPs evades *both* — those defenses
  only constrain a non-spoofing client. The real backstops against a spoofed
  flood are: (1) the CHALLENGE is only issued after Ed25519 verification, so a
  blind spoofer never gets a reply and never mints nonce state; (2) the in-flight
  semaphore (`max_inflight_packets`) caps concurrent decryption work; and (3) the
  **rejection-rate lockdown**. Pair the daemon with network-level anti-spoofing
  (uRPF/BCP 38) where you can.
* **Lockdown is an availability trade-off.** When more than
  `attack_blacklist_threshold` distinct IPs are blacklisted, or more than
  `attack_rejection_threshold` packets are rejected, within `attack_window_seconds`,
  the server enters lockdown and serves *only* source IPs that recently completed
  a handshake (the active allow-list). A sustained spoofed flood can therefore
  keep the server in lockdown and lock out **idle or first-time** legitimate
  clients (which must complete a HELLO to become active) until the flood subsides.
  This deliberately favors already-known-good sources under attack. Keep
  `active_ip_ttl_seconds` comfortably above your clients' `interval_seconds` so an
  established client stays allow-listed across the attack.
* **Strict signature verification.** Ed25519 verification uses `verify_strict`
  to avoid malleability/torsion edge cases, and X25519 key agreement rejects
  non-contributory (low-order) shared secrets.
* **Key material is zeroized.** Ed25519/X25519 secret types are built with the
  `zeroize` feature and decoded secrets are held in zeroizing storage, so keys
  are scrubbed from memory on drop.
* **In-memory state and restarts.** The nonce store and the HELLO replay cache
  live in memory and are cleared on restart. A HELLO captured shortly before a
  restart could therefore be replayed within its skew window after the restart.
  This is a small, time-bounded window and matches the nonce store's design; a
  persistent store could close it but is not implemented.
* **Clock synchronization.** HELLO freshness relies on comparing the signed
  timestamp to the server clock, so client and server should run NTP. Widen
  `hello_max_skew_seconds` for poorly-synced fleets (at the cost of a larger
  replay window before the timestamp check rejects a stale HELLO).

### Signatures vs. encryption

The two solve different problems and SignedPulse uses both:

* **Signatures (always)** provide *authenticity and integrity* — "this pulse
  really came from client X and was not altered" — and are the basis for replay
  protection. They are verifiable by the server using only the client's *public*
  key, so the server holds no client secret. This is the core guarantee and does
  not depend on encryption.
* **Encryption (optional, default on)** adds *confidentiality* so a sniffer
  cannot read the client id, nonces, or the parameter, and cannot even fingerprint
  the protocol. It uses anonymous sealed boxes to the **server's** X25519 key —
  still no per-client shared secrets. Encryption alone would not prevent replay or
  prove authenticity, which is why it complements, rather than replaces, the
  signatures.

## Testing

```sh
cargo test
```

Unit tests cover the binary codec (round-trip + bad magic/version/length),
canonical payload stability, Ed25519 sign/verify, X25519 seal/open (incl. the
reply round-trip and tamper/wrong-key failure), nonce length/expiry,
single-use/replay rejection, endpoint binding, argv `{param}` substitution, and
the IP blacklist. The integration test
(`crates/signedpulse-server/tests/handshake.rs`) drives a real UDP server with a
mock executor through a full handshake in **both** cleartext and encrypted modes,
asserts the decrypted parameter and source IP reach the hook, that a replayed
RESPONSE and an over-length parameter are rejected, and that the server stays
silent to probes.

## License

This project is source-available under the PolyForm Noncommercial License 1.0.0.

You may use, copy, modify, and distribute this software for non-commercial purposes only.

Commercial use is not permitted without a separate commercial license. This includes, but is not limited to:

- SaaS or hosted-service offerings
- managed DevOps or security services
- cloud-provider offerings
- resale
- paid consulting or support bundles based on this software
- inclusion in a paid product or platform

For commercial licensing, contact the copyright holder.
