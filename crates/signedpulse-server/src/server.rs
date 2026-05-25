//! The UDP server: receive loop, optional packet decryption, dispatch, and the
//! verification pipeline.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use signedpulse_common::config::{ServerConfig, WireEncryption};
use signedpulse_common::crypto::{self, Nonce, X25519Bytes};
use signedpulse_common::protocol::{
    hello_signing_payload, response_signing_payload, Challenge, ClientId, Hello, Packet, Response,
};
use signedpulse_common::status::{self, HookInfo, PulseInfo, ServerStatusSnapshot};
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use crate::command_runner::CommandExecutor;
use crate::nonce_store::{now_unix, ConsumeError, NonceStore};
use crate::rate_limit::{ActiveIps, Blacklist, CooldownTracker, HelloRateLimiter, LeaseTracker};
use crate::seen_cache::SeenCache;

/// Per-client state derived from config.
struct ClientInfo {
    verifying_key: VerifyingKey,
    /// Human-friendly name for logs/status (label, else short hex).
    name: String,
}

/// A fixed, valid Ed25519 public key used only to run a decoy signature check on
/// the unknown-`client_id` paths. This makes the time spent handling a HELLO or
/// RESPONSE for an unconfigured client comparable to that of a configured client
/// with a bad signature, so a scanner cannot enumerate valid client IDs by
/// timing the (always silent) drop. The verification result is discarded.
fn dummy_verifying_key() -> &'static VerifyingKey {
    use std::sync::OnceLock;
    static KEY: OnceLock<VerifyingKey> = OnceLock::new();
    KEY.get_or_init(|| ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]).verifying_key())
}

/// How a reply to this datagram must be framed.
#[derive(Clone, Copy)]
enum ReplyMode {
    /// Cleartext binary.
    Cleartext,
    /// Sealed to the peer's transport ephemeral public key.
    Sealed(X25519Bytes),
}

/// Listens for the on-demand status-dump request (SIGUSR1 on unix). On
/// non-unix platforms it simply never fires, so the daemon still runs.
struct DumpListener {
    #[cfg(unix)]
    inner: tokio::signal::unix::Signal,
}

impl DumpListener {
    fn new() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            Ok(Self {
                inner: signal(SignalKind::user_defined1())?,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }

    async fn recv(&mut self) {
        #[cfg(unix)]
        {
            self.inner.recv().await;
        }
        #[cfg(not(unix))]
        {
            std::future::pending::<()>().await;
        }
    }
}

/// Assembled server state shared across the receive loop and spawned tasks.
pub struct Server {
    config: ServerConfig,
    clients: HashMap<ClientId, ClientInfo>,
    /// X25519 secret for opening sealed datagrams and params (if configured).
    /// Held in zeroizing storage so it is scrubbed when the server is dropped.
    server_secret: Option<zeroize::Zeroizing<X25519Bytes>>,
    nonce_store: Arc<NonceStore>,
    /// Replay cache of recently accepted HELLOs, keyed by client_id + nonce.
    seen_hellos: Arc<SeenCache>,
    rate_limiter: Arc<HelloRateLimiter>,
    cooldown: Arc<CooldownTracker>,
    blacklist: Arc<Blacklist>,
    /// Source IPs that recently completed a handshake (lockdown allow-list).
    active_ips: Arc<ActiveIps>,
    /// True while we are in attack-lockdown (so the transition is logged once).
    lockdown_logged: AtomicBool,
    executor: Arc<dyn CommandExecutor>,
    /// Optional REVOKE executor; `None` when no `command.revoke_argv` is set.
    revoke_executor: Option<Arc<dyn CommandExecutor>>,
    /// Per-source-IP access leases (renewed by each verified pulse; expiry runs
    /// the revoke hook). Always tracked so the grant hook can be told `{new}`.
    leases: Arc<LeaseTracker>,
    /// Live status snapshot, dumped to `state_path` on demand (SIGUSR1).
    status: Arc<Mutex<ServerStatusSnapshot>>,
    state_path: PathBuf,
}

impl Server {
    /// Build server state from a parsed config and a command executor. Client
    /// public keys and the X25519 secret are decoded up front so bad material
    /// fails fast at startup.
    pub fn from_config(
        config: ServerConfig,
        executor: Arc<dyn CommandExecutor>,
        revoke_executor: Option<Arc<dyn CommandExecutor>>,
    ) -> anyhow::Result<Self> {
        let mut clients = HashMap::new();
        for c in &config.clients {
            let id = ClientId::from_hex(&c.client_id)
                .map_err(|_| anyhow::anyhow!("client {:?} has a non-hex client_id", c.client_id))?;
            let verifying_key = crypto::load_verifying_key(&c.public_key).map_err(|e| {
                anyhow::anyhow!("client {:?} has an invalid public_key: {e}", c.client_id)
            })?;
            let name = c
                .label
                .clone()
                .unwrap_or_else(|| format!("{}…", &c.client_id[..12.min(c.client_id.len())]));
            clients.insert(
                id,
                ClientInfo {
                    verifying_key,
                    name,
                },
            );
        }

        let server_secret = match &config.server.encryption_private_key {
            Some(b64) => Some(zeroize::Zeroizing::new(
                crypto::x25519_from_base64(b64)
                    .map_err(|e| anyhow::anyhow!("invalid server.encryption_private_key: {e}"))?,
            )),
            None => None,
        };

        let s = &config.server;
        let rate_limiter = Arc::new(HelloRateLimiter::new(
            s.hello_rate_max,
            s.hello_rate_window_seconds,
            s.max_tracked_ips,
        ));
        let cooldown = Arc::new(CooldownTracker::new(s.client_cooldown_seconds));
        let blacklist = Arc::new(Blacklist::new(
            s.max_faulty_packets,
            s.blacklist_seconds,
            s.attack_blacklist_threshold,
            s.attack_rejection_threshold,
            s.attack_window_seconds,
            s.max_tracked_ips,
        ));
        let active_ips = Arc::new(ActiveIps::new(s.active_ip_ttl_seconds, s.max_tracked_ips));
        let leases = Arc::new(LeaseTracker::new(s.max_tracked_ips));

        let state_path = s
            .state_file
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| status::default_state_path("server"));
        let status = Arc::new(Mutex::new(ServerStatusSnapshot {
            started_at_unix: now_unix(),
            pid: std::process::id(),
            ..Default::default()
        }));

        Ok(Server {
            clients,
            server_secret,
            nonce_store: Arc::new(NonceStore::new()),
            seen_hellos: Arc::new(SeenCache::new()),
            rate_limiter,
            cooldown,
            blacklist,
            active_ips,
            lockdown_logged: AtomicBool::new(false),
            executor,
            revoke_executor,
            leases,
            status,
            state_path,
            config,
        })
    }

    pub fn server_id(&self) -> &str {
        &self.config.server.server_id
    }

    /// Serialize the current live status to the state file. Called on SIGUSR1
    /// and directly from tests. Errors are logged, not fatal.
    pub fn write_status(&self) {
        let mut snapshot = self.status.lock().unwrap().clone();
        snapshot.active_leases = self.leases.active_count();
        if let Err(e) = status::write_snapshot(&self.state_path, &snapshot) {
            warn!(path = %self.state_path.display(), error = %e, "failed to write status file");
        }
    }

    /// Sweep expired access leases and run the revoke hook for each. Called every
    /// cleanup tick (and directly from tests). Always drains the expired entries
    /// (so the map stays bounded and `{new}` stays accurate); runs the revoke
    /// hook only when one is configured.
    ///
    /// The expired leases are processed in a SINGLE spawned task, sequentially
    /// (one revoke in flight at a time), so within a tick the executor's
    /// `try_acquire` capacity is never exceeded and no revoke is lost to
    /// `AtCapacity`. (Edge case: if a revoke hook runs longer than the 5s tick,
    /// the next tick's batch can overlap this one; with `command.max_concurrent`
    /// revokes already in flight a further revoke would get `AtCapacity` and be
    /// dropped — that IP then stays open until it re-pulses and re-expires. This
    /// needs a revoke hook slower than the tick AND the concurrency cap reached,
    /// and is self-healing.) Before each revoke we re-check that the IP has not
    /// re-pulsed in the meantime — if a fresh lease now exists, a concurrent
    /// grant re-opened access and we must NOT revoke it.
    pub fn run_lease_scan(self: &Arc<Self>) {
        let expired = self.leases.take_expired();
        let Some(revoke) = self.revoke_executor.clone() else {
            return;
        };
        if expired.is_empty() {
            return;
        }
        let leases = self.leases.clone();
        let status = self.status.clone();
        tokio::spawn(async move {
            for e in expired {
                // The IP re-pulsed and holds a fresh lease again — skip the stale
                // revoke so we don't tear down access a new grant just re-opened.
                if leases.is_live(e.ip) {
                    continue;
                }
                match revoke
                    .execute(&e.client_id, e.ip, e.source_port, e.param.as_deref(), false)
                    .await
                {
                    Ok(result) => {
                        if result.timed_out {
                            warn!(ip = %e.ip, "revoke hook timed out");
                        } else {
                            info!(ip = %e.ip, client_id = %e.client_id, exit_code = ?result.exit_code, "lease expired; access revoked");
                        }
                        let mut s = status.lock().unwrap();
                        s.last_revoke = Some(HookInfo {
                            client_id: e.client_id,
                            source_ip: e.ip,
                            at_unix: now_unix(),
                            exit_code: result.exit_code,
                            timed_out: result.timed_out,
                            param: e.param,
                        });
                    }
                    Err(err) => error!(ip = %e.ip, error = %err, "revoke hook failed"),
                }
            }
        });
    }

    /// Count a rejected packet (validation/auth failure). Does NOT touch the
    /// blacklist — these packets already decrypted and decoded, so they are not
    /// the cheap-to-detect garbage the blacklist defends against, and counting
    /// them would let rate-limited or misconfigured (or shared-NAT) clients
    /// blacklist a legitimate IP.
    fn note_rejected(&self, replay: bool) {
        {
            let mut s = self.status.lock().unwrap();
            s.rejected += 1;
            if replay {
                s.replays += 1;
            }
        }
        // Feed the rejection-rate lockdown trigger so a sustained flood of
        // well-formed-but-unauthenticated packets engages lockdown too.
        self.blacklist.note_rejection();
    }

    /// Count a *faulty* packet — one that failed to decrypt or decode, i.e. the
    /// cheap-to-detect garbage an attacker would flood. Feeds the per-IP blacklist
    /// so such a flood cannot keep burning CPU on decryption attempts. Logs only
    /// the first time an IP is blacklisted; further packets are dropped silently
    /// at the `is_blocked` gate.
    fn note_faulty(&self, ip: IpAddr) {
        self.note_rejected(false);
        if self.blacklist.record_faulty(ip) {
            warn!(%ip, "source IP blacklisted after repeated faulty packets");
        }
    }

    /// Run the receive loop on an already-bound socket until `shutdown` resolves.
    pub async fn run<F>(self: Arc<Self>, socket: UdpSocket, shutdown: F) -> anyhow::Result<()>
    where
        F: Future<Output = ()> + Send,
    {
        let socket = Arc::new(socket);
        let local = socket.local_addr()?;
        info!(
            bind = %local,
            server_id = %self.config.server.server_id,
            clients = self.clients.len(),
            wire_encryption = ?self.config.server.wire_encryption,
            "signedpulse server started"
        );

        let pid_path = status::pid_path(&self.state_path);
        if let Err(e) = status::write_pidfile(&pid_path) {
            warn!(path = %pid_path.display(), error = %e, "failed to write pid file");
        }
        let mut dump = DumpListener::new()?;

        // Background task: purge expired nonces, stale rate-limit windows, and
        // expired blacklist entries.
        let cleanup = {
            let server = Arc::clone(&self);
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(5));
                loop {
                    tick.tick().await;
                    let now = now_unix();
                    let removed = server.nonce_store.purge_expired(now);
                    if removed > 0 {
                        debug!(removed, "purged expired nonces");
                    }
                    server.seen_hellos.purge_expired(now);
                    server.rate_limiter.purge_stale();
                    server.blacklist.purge_stale();
                    server.active_ips.purge_stale();
                    server.cooldown.purge_stale();
                    // Revoke access for IPs whose lease expired this tick.
                    server.run_lease_scan();
                }
            })
        };

        let max = self.config.server.max_packet_size;
        // One extra byte so a datagram of exactly `max` bytes is received intact
        // and only genuinely oversized ones (len > max) are detected/dropped.
        let mut buf = vec![0u8; max + 1];

        // Bound the number of datagrams processed concurrently so a flood cannot
        // spawn unbounded decryption/verification work (and unbounded tasks).
        let inflight = Arc::new(tokio::sync::Semaphore::new(
            if self.config.server.max_inflight_packets == 0 {
                tokio::sync::Semaphore::MAX_PERMITS
            } else {
                self.config.server.max_inflight_packets
            },
        ));

        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    info!("shutdown signal received, stopping receive loop");
                    break;
                }
                _ = dump.recv() => {
                    self.write_status();
                    debug!("status dumped on request");
                }
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok((len, peer)) => {
                            if len > max {
                                warn!(%peer, len, "dropping oversized packet");
                                continue;
                            }
                            // Cheap source-IP gates BEFORE any allocation, task
                            // spawn, or decryption — so a flood (even spoofed) is
                            // shed as early as possible.
                            let ip = peer.ip();
                            if self.blacklist.is_blocked(ip) {
                                continue;
                            }
                            if self.blacklist.under_attack() {
                                if !self.lockdown_logged.swap(true, Ordering::Relaxed) {
                                    warn!("under attack: entering lockdown, only serving recently-active source IPs");
                                }
                                if !self.active_ips.is_active(ip) {
                                    // Keep lockdown latched while the flood from
                                    // non-active sources continues. NOTE: this is
                                    // the ONLY caller of note_lockdown_drop, and it
                                    // runs on the single receive-loop task (before
                                    // any spawn), which is what makes its Relaxed
                                    // load-then-store window counter race-free. Do
                                    // not move this accounting into a spawned task.
                                    self.blacklist.note_lockdown_drop();
                                    continue;
                                }
                            } else {
                                self.lockdown_logged.store(false, Ordering::Relaxed);
                            }
                            // Bound concurrent work; drop rather than queue at capacity.
                            let permit = match inflight.clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => continue,
                            };
                            let data = buf[..len].to_vec();
                            let server = self.clone();
                            let socket = socket.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                server.handle_datagram(&data, peer, &socket).await;
                            });
                        }
                        Err(e) => {
                            error!(error = %e, "recv_from failed");
                        }
                    }
                }
            }
        }

        cleanup.abort();
        let _ = std::fs::remove_file(&pid_path);
        Ok(())
    }

    async fn handle_datagram(&self, data: &[u8], peer: SocketAddr, socket: &UdpSocket) {
        // The recv loop has already applied the cheap source-IP gates (blacklist
        // + attack lockdown) before spawning us.
        //
        // 1. Recover the cleartext inner packet bytes + how to frame any reply.
        //    Silent-drop policy: the only reply we ever emit is a CHALLENGE to a
        //    fully validated HELLO; everything else drops with no response.
        let (packet_bytes, reply) = match self.config.server.wire_encryption {
            WireEncryption::Required => {
                let secret = match &self.server_secret {
                    Some(s) => s,
                    None => {
                        // Misconfiguration; cannot decrypt anything.
                        return;
                    }
                };
                match crypto::open(secret, data, crypto::CTX_WIRE) {
                    Ok((inner, peer_eph)) => (inner, ReplyMode::Sealed(peer_eph)),
                    Err(_) => {
                        // Undecryptable: the expensive case we most want to bound.
                        self.note_faulty(peer.ip());
                        return;
                    }
                }
            }
            WireEncryption::Off => (data.to_vec(), ReplyMode::Cleartext),
        };

        let packet = match Packet::decode(&packet_bytes) {
            Ok(p) => p,
            Err(e) => {
                warn!(%peer, error = %e, "rejected malformed packet");
                self.note_faulty(peer.ip());
                return;
            }
        };

        match packet {
            Packet::Hello(hello) => self.handle_hello(hello, peer, socket, reply).await,
            Packet::Response(resp) => self.handle_response(resp, peer).await,
            Packet::Challenge(_) => {
                warn!(%peer, "ignoring unexpected challenge packet sent to server");
                self.note_rejected(false);
            }
        }
    }

    /// Encode `packet` and send it to `peer`, sealing it when the request was
    /// encrypted.
    async fn send_reply(
        &self,
        packet: Packet,
        peer: SocketAddr,
        socket: &UdpSocket,
        reply: ReplyMode,
        bind: &[u8],
    ) -> bool {
        let bytes = packet.encode();
        let datagram = match reply {
            ReplyMode::Cleartext => bytes,
            ReplyMode::Sealed(peer_eph) => {
                // Authenticate the reply with the server's static key so only we
                // can produce a CHALLENGE the client will accept, and bind it to
                // this HELLO's nonce so it can't be replayed into the client.
                let secret = match &self.server_secret {
                    Some(s) => s,
                    None => return false,
                };
                match crypto::seal_reply(secret, &peer_eph, &bytes, bind) {
                    Ok(blob) => blob,
                    Err(e) => {
                        error!(%peer, error = %e, "failed to seal reply");
                        return false;
                    }
                }
            }
        };
        match socket.send_to(&datagram, peer).await {
            Ok(_) => true,
            Err(e) => {
                error!(%peer, error = %e, "failed to send reply");
                false
            }
        }
    }

    async fn handle_hello(
        &self,
        hello: Hello,
        peer: SocketAddr,
        socket: &UdpSocket,
        reply: ReplyMode,
    ) {
        // 1. Rate-limit by the source IP from packet metadata.
        if !self.rate_limiter.check(peer.ip()) {
            warn!(%peer, "rate limit exceeded for HELLO");
            self.note_rejected(false);
            return;
        }

        let client_hex = hello.client_id.to_hex();

        // 2. The client must be configured.
        let info = match self.clients.get(&hello.client_id) {
            Some(info) => info,
            None => {
                // Decoy verification so an unknown client_id is not faster (and
                // thus distinguishable) from a known client with a bad signature.
                let payload = hello_signing_payload(
                    &self.config.server.server_id,
                    &client_hex,
                    hello.client_timestamp_unix,
                    &B64.encode(hello.hello_nonce),
                );
                let _ =
                    crypto::verify_payload_raw(dummy_verifying_key(), &payload, &hello.signature);
                warn!(%peer, client_id = %hello.client_id, "HELLO from unknown client_id");
                self.note_rejected(false);
                return;
            }
        };

        // 3. Authenticate the HELLO (restricts replies to key-holding clients).
        let payload = hello_signing_payload(
            &self.config.server.server_id,
            &client_hex,
            hello.client_timestamp_unix,
            &B64.encode(hello.hello_nonce),
        );
        if crypto::verify_payload_raw(&info.verifying_key, &payload, &hello.signature).is_err() {
            warn!(%peer, client = %info.name, "unauthorized HELLO: invalid signature");
            self.note_rejected(false);
            return;
        }

        // 4. Freshness window. Compute in i128 so an attacker-supplied i64
        //    timestamp (e.g. i64::MIN) can't overflow the subtraction or abs().
        let now = now_unix();
        let skew = self.config.server.hello_max_skew_seconds as i128;
        let drift = (now as i128 - hello.client_timestamp_unix as i128).abs();
        if drift > skew {
            warn!(%peer, client = %info.name, "HELLO timestamp outside skew window");
            self.note_rejected(false);
            return;
        }

        // 5. HELLO replay defense (fresh per-HELLO nonce, single-use in window).
        let mut replay_key = hello.client_id.0.to_vec();
        replay_key.push(0);
        replay_key.extend_from_slice(&hello.hello_nonce);
        let seen_ttl = self.config.server.hello_max_skew_seconds.saturating_mul(2);
        if !self.seen_hellos.insert_if_absent(replay_key, now, seen_ttl) {
            warn!(%peer, client = %info.name, "HELLO replay detected");
            self.note_rejected(true);
            return;
        }

        info!(%peer, client = %info.name, "HELLO received");

        // This source is now a known-good, authenticated endpoint: allow it
        // through during an attack lockdown (so its RESPONSE can complete).
        self.active_ips.mark(peer.ip());

        let nonce = Nonce::generate();
        // Compute the expiry ONCE; the same value goes into the CHALLENGE (which
        // the client signs) and the nonce store (which the server verifies).
        let expires_at = (now as i128 + self.config.server.nonce_ttl_seconds as i128)
            .min(i64::MAX as i128) as i64;
        self.nonce_store.insert(
            nonce.0.to_vec(),
            client_hex,
            peer.ip(),
            peer.port(),
            expires_at,
        );

        let challenge = Packet::Challenge(Challenge {
            client_id: hello.client_id,
            nonce: nonce.0,
            expires_at_unix: expires_at,
        });
        if self
            .send_reply(challenge, peer, socket, reply, &hello.hello_nonce)
            .await
        {
            info!(%peer, client = %info.name, "challenge issued");
            self.status.lock().unwrap().hello_accepted += 1;
        }
    }

    async fn handle_response(&self, resp: Response, peer: SocketAddr) {
        let client_hex = resp.client_id.to_hex();

        // 1. Client must be configured.
        let info = match self.clients.get(&resp.client_id) {
            Some(info) => info,
            None => {
                // Decoy verification (see handle_hello) so an unknown client_id
                // is not distinguishable by timing from a bad signature.
                let param_b64 = resp
                    .param
                    .as_ref()
                    .map(|b| B64.encode(b))
                    .unwrap_or_default();
                let payload = response_signing_payload(
                    &self.config.server.server_id,
                    &client_hex,
                    &B64.encode(resp.nonce),
                    resp.interval_seconds,
                    0,
                    &param_b64,
                );
                let _ =
                    crypto::verify_payload_raw(dummy_verifying_key(), &payload, &resp.signature);
                warn!(%peer, client_id = %resp.client_id, "RESPONSE from unknown client_id");
                self.note_rejected(false);
                return;
            }
        };
        let name = info.name.clone();

        // 2. Validate (peek) the nonce WITHOUT consuming it — single-use, expiry,
        //    client + exact source IP:port binding — to obtain the stored expiry
        //    for the signed payload. We verify the signature before consuming so
        //    a bad-signature packet cannot burn the nonce.
        let entry = match self.nonce_store.validate(
            &resp.nonce,
            &client_hex,
            peer.ip(),
            peer.port(),
            now_unix(),
        ) {
            Ok(entry) => entry,
            Err(e) => {
                let msg = e.reason();
                let replay = e == ConsumeError::AlreadyUsed;
                warn!(%peer, client = %name, "nonce rejected: {msg}");
                self.note_rejected(replay);
                return;
            }
        };

        // 3. Verify the signature over the canonical payload (param ciphertext
        //    base64 included — encrypt-then-sign).
        let param_b64 = resp
            .param
            .as_ref()
            .map(|b| B64.encode(b))
            .unwrap_or_default();
        let payload = response_signing_payload(
            &self.config.server.server_id,
            &client_hex,
            &B64.encode(resp.nonce),
            resp.interval_seconds,
            entry.expires_at_unix,
            &param_b64,
        );
        if crypto::verify_payload_raw(&info.verifying_key, &payload, &resp.signature).is_err() {
            warn!(%peer, client = %name, "invalid signature; not executing command");
            self.note_rejected(false);
            return;
        }

        // 4. Now consume the nonce — the atomic single-use gate. A concurrent
        //    duplicate that also passed `validate` loses the race here and is
        //    rejected as a replay, so no double-execution is possible.
        if let Err(e) =
            self.nonce_store
                .consume(&resp.nonce, &client_hex, peer.ip(), peer.port(), now_unix())
        {
            let replay = e == ConsumeError::AlreadyUsed;
            warn!(%peer, client = %name, "nonce rejected at consume: {}", e.reason());
            self.note_rejected(replay);
            return;
        }

        // 4. Decrypt the optional parameter and validate it.
        let param = match self.decrypt_param(resp.param.as_deref(), peer, &name) {
            Ok(p) => p,
            Err(()) => return, // already counted/logged
        };

        info!(%peer, client = %name, "response verified");
        self.active_ips.mark(peer.ip());

        // Record the verified pulse.
        {
            let pulse = PulseInfo {
                source_ip: peer.ip(),
                source_port: peer.port(),
                at_unix: now_unix(),
            };
            let mut s = self.status.lock().unwrap();
            s.verified += 1;
            s.last_pulse = Some(pulse.clone());
            s.clients.insert(name.clone(), pulse);
        }

        // 5. Renew the access lease on EVERY verified pulse — even if the cooldown
        //    below skips the grant hook — so the IP stays authorized while it keeps
        //    pulsing. The TTL is derived from the client's advertised interval, so
        //    the server knows when to expect the next pulse. `is_new` is true when
        //    there was no live lease (first pulse, or first after a prior expiry):
        //    a new/reactivated session, surfaced to the grant hook as `{new}`.
        let lease_ttl = {
            let s = &self.config.server;
            let secs = (resp.interval_seconds as u64)
                .saturating_mul(s.lease_grace_multiplier as u64)
                .clamp(1, s.lease_max_seconds);
            Duration::from_secs(secs)
        };
        let is_new = self.leases.renew(
            peer.ip(),
            &client_hex,
            peer.port(),
            param.as_deref(),
            lease_ttl,
        );

        // 6. Cooldown (per client_id and per source IP). A new/reactivated
        //    session (is_new) always (re)runs the grant hook so access is
        //    (re)opened even within the cooldown window — otherwise a client
        //    whose lease just expired (pinhole revoked) and resumed could be left
        //    with a live lease but a closed pinhole until cooldown lapsed.
        let ip_key = format!("ip:{}", peer.ip());
        let id_key = format!("id:{client_hex}");
        if !is_new && (self.cooldown.in_cooldown(&id_key) || self.cooldown.in_cooldown(&ip_key)) {
            info!(%peer, client = %name, "within cooldown; skipping command execution");
            return;
        }

        // 7. Execute the grant hook with the source IP from packet metadata. The
        //    hook receives the canonical 64-hex client id (not the human label),
        //    so {client_id} is the verified identity an attacker cannot shape.
        let source_ip = peer.ip();
        let source_port = peer.port();
        match self
            .executor
            .execute(
                &client_hex,
                source_ip,
                source_port,
                param.as_deref(),
                is_new,
            )
            .await
        {
            Ok(result) => {
                self.cooldown.mark(&id_key);
                self.cooldown.mark(&ip_key);
                self.status.lock().unwrap().last_hook = Some(HookInfo {
                    client_id: name.clone(),
                    source_ip,
                    at_unix: now_unix(),
                    exit_code: result.exit_code,
                    timed_out: result.timed_out,
                    param,
                });
                if result.timed_out {
                    warn!(%peer, client = %name, "command timed out");
                } else {
                    info!(%peer, client = %name, source_ip = %source_ip, exit_code = ?result.exit_code, "command executed");
                }
            }
            Err(e) => error!(%peer, client = %name, error = %e, "command execution failed"),
        }
    }

    /// Decrypt and validate the optional sealed parameter blob. Returns
    /// `Ok(None)` when there is no param, `Ok(Some(plaintext))` on success, and
    /// `Err(())` (already counted as a rejection) on any failure.
    fn decrypt_param(
        &self,
        blob: Option<&[u8]>,
        peer: SocketAddr,
        name: &str,
    ) -> Result<Option<String>, ()> {
        let blob = match blob {
            Some(b) => b,
            None => return Ok(None),
        };
        let secret = match &self.server_secret {
            Some(s) => s,
            None => {
                warn!(%peer, client = %name, "param present but server has no encryption key");
                self.note_rejected(false);
                return Err(());
            }
        };
        let plaintext = match crypto::open(secret, blob, crypto::CTX_PARAM) {
            Ok((pt, _)) => pt,
            Err(_) => {
                warn!(%peer, client = %name, "param failed to decrypt");
                self.note_rejected(false);
                return Err(());
            }
        };
        if plaintext.len() > self.config.server.max_param_len {
            warn!(%peer, client = %name, "param exceeds max length");
            self.note_rejected(false);
            return Err(());
        }
        let text = match std::str::from_utf8(&plaintext) {
            Ok(t) if !t.chars().any(|c| c.is_control()) => t.to_string(),
            _ => {
                warn!(%peer, client = %name, "param is not clean UTF-8 text");
                self.note_rejected(false);
                return Err(());
            }
        };
        // Defense-in-depth: refuse a param that would be parsed as an option by
        // the hook (argument injection). Hooks should still treat {param} as a
        // value, but a leading '-' is never legitimate here.
        if text.starts_with('-') {
            warn!(%peer, client = %name, "param starts with '-'; rejecting (option-injection guard)");
            self.note_rejected(false);
            return Err(());
        }
        Ok(Some(text))
    }
}
