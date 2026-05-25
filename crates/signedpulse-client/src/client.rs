//! The client side of the handshake and the periodic run loop.
//!
//! A client can pulse several servers at once: `[client]` is the primary server
//! and each `[client.servers.<server_id>]` adds another. All targets share the
//! client identity (`client_id`/signing key) but run independent pulse loops,
//! each with its own address, server key, and timing. Their live status is
//! collected per-`server_id` into one [`ClientStatusSnapshot`].

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use signedpulse_common::config::{ClientConfig, ClientSection, ServerOverride};
use signedpulse_common::crypto::{self, Nonce, X25519Bytes};
use signedpulse_common::protocol::{
    bye_signing_payload, hello_signing_payload, response_signing_payload, Bye, ClientId, Hello,
    Packet, Response,
};
use signedpulse_common::status::{self, ClientStatusSnapshot, ServerLegStatus};
use tokio::net::UdpSocket;
use tracing::{error, info, warn};
use zeroize::Zeroizing;

/// Listens for the on-demand status-dump request (SIGUSR1 on unix). On
/// non-unix platforms it never fires, so the client still runs normally.
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

/// One fully-resolved server target the client pulses. Built from `[client]`
/// (primary) and each `[client.servers.<name>]` entry, with inheritance applied.
#[derive(Clone)]
struct ServerTarget {
    /// Local label (status key / config table key). Unique within this client.
    name: String,
    /// The id signed into the payload; must match the remote server's server_id.
    server_id: String,
    server_addr: String,
    /// Server X25519 public key for wire/param encryption, if configured.
    server_pub: Option<X25519Bytes>,
    wire_encryption: bool,
    interval: Duration,
    /// SIP-style retry backoff: per-attempt CHALLENGE wait =
    /// min(retry_initial × 2^(k-1), retry_max).
    retry_initial: Duration,
    retry_max: Duration,
    retries: u32,
    param_command: Option<Vec<String>>,
    param_command_timeout: Duration,
    param_max_len: usize,
}

/// Whether a handshake renews the access lease (a normal pulse / RESPONSE) or
/// releases it early (a BYE — clean shutdown). Both share the same
/// HELLO → CHALLENGE → … exchange and single-use nonce; only the final signed
/// packet differs, with a distinct signing payload so neither can be replayed
/// as the other.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Renew,
    Release,
}

/// Holds the shared client identity and the resolved set of server targets.
pub struct Client {
    signing_key: SigningKey,
    client_id: ClientId,
    targets: Vec<ServerTarget>,
    status: Arc<Mutex<ClientStatusSnapshot>>,
    state_path: PathBuf,
    /// Send a signed BYE to each server on graceful shutdown (releases leases now).
    bye_on_shutdown: bool,
}

impl Client {
    pub fn from_config(config: ClientConfig) -> anyhow::Result<Self> {
        let c = &config.client;
        let signing_key = crypto::load_signing_key(&c.private_key)
            .map_err(|e| anyhow::anyhow!("invalid private_key in client config: {e}"))?;
        let client_id = ClientId::from_hex(&c.client_id)
            .map_err(|_| anyhow::anyhow!("client.client_id must be 64 hex characters"))?;

        // The primary server comes from the [client] fields directly; its local
        // label is its server_id.
        let mut targets = vec![resolve_target(
            c.server_id.clone(),
            c.server_id.clone(),
            &c.server_addr,
            c.server_encryption_key.as_deref(),
            c.wire_encryption,
            c.interval_seconds,
            c.retry_initial_ms,
            c.retry_max_ms,
            c.retries,
            c.param_command.clone(),
            c.param_command_timeout_seconds,
            c.param_max_len,
        )?];
        // Additional servers inherit unset fields from [client]. Their key is the
        // server_id; each carries its own address and (own, never inherited) key.
        for (id, ov) in &c.servers {
            targets.push(resolve_override(id, ov, c)?);
        }

        // Seed the per-server status legs, keyed by the local label.
        let mut legs = BTreeMap::new();
        for t in &targets {
            legs.insert(
                t.name.clone(),
                ServerLegStatus {
                    server_addr: t.server_addr.clone(),
                    server_id: t.server_id.clone(),
                    interval_seconds: t.interval.as_secs(),
                    last_result: "pending".to_string(),
                    ..Default::default()
                },
            );
        }
        let status = Arc::new(Mutex::new(ClientStatusSnapshot {
            started_at_unix: now_unix(),
            pid: std::process::id(),
            servers: legs,
        }));

        let state_path = c
            .state_file
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| status::default_state_path("client"));

        Ok(Client {
            signing_key,
            client_id,
            targets,
            status,
            state_path,
            bye_on_shutdown: c.bye_on_shutdown,
        })
    }

    /// Serialize the current live status to the state file. Errors are logged.
    fn write_status(&self) {
        let snapshot = self.status.lock().unwrap().clone();
        if let Err(e) = status::write_snapshot(&self.state_path, &snapshot) {
            warn!(path = %self.state_path.display(), error = %e, "failed to write status file");
        }
    }

    /// Run until `shutdown` resolves: spawn one pulse loop per server target and
    /// serve on-demand status dumps (SIGUSR1). On a clean shutdown, if
    /// `bye_on_shutdown` is set, send a signed BYE to each server so their access
    /// leases are released immediately instead of waiting to time out.
    pub async fn run_forever<F>(&self, shutdown: F) -> anyhow::Result<()>
    where
        F: std::future::Future<Output = ()>,
    {
        info!(
            client_id = %self.client_id.to_hex(),
            servers = self.targets.len(),
            "signedpulse client started"
        );

        let pid_path = status::pid_path(&self.state_path);
        if let Err(e) = status::write_pidfile(&pid_path) {
            warn!(path = %pid_path.display(), error = %e, "failed to write pid file");
        }
        let mut dump = DumpListener::new()?;

        // Spawn one supervised pulse loop per server target. `run_loop` never
        // returns normally (it loops forever), so a leg finishing means it
        // panicked. Rather than let it die silently behind a healthy-looking
        // process, we surface it and exit non-zero so the service manager
        // restarts all legs.
        let mut legs = tokio::task::JoinSet::new();
        for target in &self.targets {
            let pulser = self.pulser_for(target);
            let name = target.name.clone();
            legs.spawn(async move {
                pulser.run_loop().await;
                name
            });
        }

        // Stay alive to answer status-dump requests; abort if any leg stops;
        // stop cleanly when the shutdown signal arrives.
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    info!("shutdown signal received, stopping pulse loops");
                    break;
                }
                _ = dump.recv() => self.write_status(),
                joined = legs.join_next() => match joined {
                    Some(Ok(name)) => {
                        error!(server = %name, "pulse leg exited unexpectedly");
                        anyhow::bail!("pulse leg {name:?} stopped");
                    }
                    Some(Err(e)) => {
                        error!(error = %e, "a pulse leg panicked");
                        anyhow::bail!("a pulse leg panicked: {e}");
                    }
                    None => anyhow::bail!("no pulse legs are running"),
                },
            }
        }

        // Stop renewing leases (dropping the JoinSet aborts every leg), then
        // best-effort release each lease with a signed BYE.
        legs.abort_all();
        drop(legs);
        if self.bye_on_shutdown {
            self.send_bye_all().await;
        }
        Ok(())
    }

    /// Best-effort: send a signed BYE to every server so its access lease is
    /// released now. Failures are logged, not fatal — a dropped BYE just means
    /// the lease times out as it would have without this feature.
    async fn send_bye_all(&self) {
        info!(servers = self.targets.len(), "releasing leases (BYE)");
        for target in &self.targets {
            let pulser = self.pulser_for(target);
            match pulser.run_cycle(1, Mode::Release, None).await {
                Ok(()) => info!(server = %target.name, "sent BYE; lease released"),
                Err(e) => warn!(server = %target.name, error = %e, "failed to send BYE"),
            }
        }
    }

    /// Build a single-shot `Pulser` for `target` (shares the signing key,
    /// client id, and status snapshot).
    fn pulser_for(&self, target: &ServerTarget) -> Pulser {
        Pulser {
            signing_key: self.signing_key.clone(),
            client_id: self.client_id,
            target: target.clone(),
            status: self.status.clone(),
        }
    }

    /// One-shot pulse: renew the lease on every configured server and exit. With
    /// `retry` false (`pulse`) each server gets exactly one attempt; with `retry`
    /// true (`ping`) the configured SIP retry/backoff is used. `param`, when set,
    /// overrides `param_command` for this run (an ad-hoc one-shot parameter).
    pub async fn run_once(&self, retry: bool, param: Option<&str>) -> anyhow::Result<()> {
        self.run_targets(Mode::Renew, retry, param).await
    }

    /// One-shot release: send a signed BYE to every configured server (the `bye`
    /// subcommand). One attempt per server; prints a per-server result line.
    /// `param`, when set, is sealed and passed to the server's revoke hook.
    pub async fn release_all(&self, param: Option<&str>) -> anyhow::Result<()> {
        self.run_targets(Mode::Release, false, param).await
    }

    /// Run one handshake (`mode`) against every configured server, printing a
    /// per-server result line and returning `Err` if any server failed, so the
    /// process exit code reflects success (useful in scripts/cron).
    async fn run_targets(
        &self,
        mode: Mode,
        retry: bool,
        param: Option<&str>,
    ) -> anyhow::Result<()> {
        let ok_word = match mode {
            Mode::Renew => "ok",
            Mode::Release => "released",
        };
        let mut failures = 0usize;
        for target in &self.targets {
            let pulser = self.pulser_for(target);
            let attempts = if retry { target.retries.max(1) } else { 1 };
            match pulser.run_cycle(attempts, mode, param).await {
                Ok(()) => println!("{} ({}): {ok_word}", target.name, target.server_addr),
                Err(e) => {
                    println!("{} ({}): FAILED — {e}", target.name, target.server_addr);
                    failures += 1;
                }
            }
        }
        if failures > 0 {
            anyhow::bail!(
                "{failures}/{} server(s) did not respond",
                self.targets.len()
            );
        }
        Ok(())
    }
}

/// Build a target from explicit values (used for the primary [client] server).
#[allow(clippy::too_many_arguments)]
fn resolve_target(
    name: String,
    server_id: String,
    server_addr: &str,
    enc_key_b64: Option<&str>,
    wire_encryption: bool,
    interval_seconds: u64,
    retry_initial_ms: u64,
    retry_max_ms: u64,
    retries: u32,
    param_command: Option<Vec<String>>,
    param_command_timeout_seconds: u64,
    param_max_len: usize,
) -> anyhow::Result<ServerTarget> {
    let server_pub = match enc_key_b64 {
        Some(b64) => Some(
            crypto::x25519_from_base64(b64)
                .map_err(|e| anyhow::anyhow!("invalid server_encryption_key for {name}: {e}"))?,
        ),
        None => None,
    };
    if wire_encryption && server_pub.is_none() {
        anyhow::bail!("server {name}: wire_encryption is on but server_encryption_key is missing");
    }
    if param_command.is_some() && server_pub.is_none() {
        anyhow::bail!("server {name}: param_command requires server_encryption_key");
    }
    Ok(ServerTarget {
        name,
        server_id,
        server_addr: server_addr.to_string(),
        server_pub,
        wire_encryption,
        interval: Duration::from_secs(interval_seconds),
        retry_initial: Duration::from_millis(retry_initial_ms),
        retry_max: Duration::from_millis(retry_max_ms),
        retries,
        param_command,
        param_command_timeout: Duration::from_secs(param_command_timeout_seconds),
        param_max_len,
    })
}

/// Build a secondary target, inheriting unset fields from `[client]`. The local
/// label is the config table key; the wire `server_id` defaults to that label
/// unless the entry overrides it.
fn resolve_override(
    name: &str,
    ov: &ServerOverride,
    base: &ClientSection,
) -> anyhow::Result<ServerTarget> {
    resolve_target(
        name.to_string(),
        ov.server_id.clone().unwrap_or_else(|| name.to_string()),
        &ov.server_addr,
        ov.server_encryption_key.as_deref(),
        ov.wire_encryption.unwrap_or(base.wire_encryption),
        ov.interval_seconds.unwrap_or(base.interval_seconds),
        ov.retry_initial_ms.unwrap_or(base.retry_initial_ms),
        ov.retry_max_ms.unwrap_or(base.retry_max_ms),
        ov.retries.unwrap_or(base.retries),
        ov.param_command
            .clone()
            .or_else(|| base.param_command.clone()),
        ov.param_command_timeout_seconds
            .unwrap_or(base.param_command_timeout_seconds),
        ov.param_max_len.unwrap_or(base.param_max_len),
    )
}

/// One server's pulse loop. Owns everything it needs so it can run on its own
/// task; shares the live status map so its leg is visible to `status`.
struct Pulser {
    signing_key: SigningKey,
    client_id: ClientId,
    target: ServerTarget,
    status: Arc<Mutex<ClientStatusSnapshot>>,
}

impl Pulser {
    async fn run_loop(self) {
        info!(
            server = %self.target.name,
            server_id = %self.target.server_id,
            addr = %self.target.server_addr,
            interval_s = self.target.interval.as_secs(),
            wire_encryption = self.target.wire_encryption,
            "pulsing server"
        );
        loop {
            let now = now_unix();
            // Record the attempt time up front so a leg that's mid-cycle (a
            // handshake can take several seconds across retries) shows as active
            // rather than idle/pending in `status`.
            if let Some(leg) = self
                .status
                .lock()
                .unwrap()
                .servers
                .get_mut(&self.target.name)
            {
                leg.last_attempt_at_unix = Some(now);
            }
            let result = self.run_cycle(self.target.retries, Mode::Renew, None).await;
            {
                let mut s = self.status.lock().unwrap();
                if let Some(leg) = s.servers.get_mut(&self.target.name) {
                    match &result {
                        Ok(()) => {
                            leg.last_success_at_unix = Some(now);
                            leg.last_result = "ok".to_string();
                        }
                        Err(e) => leg.last_result = e.to_string(),
                    }
                }
            }
            if let Err(e) = result {
                warn!(server = %self.target.name, error = %e, "pulse cycle failed");
            }
            tokio::time::sleep(self.target.interval).await;
        }
    }

    /// One full HELLO → CHALLENGE → RESPONSE|BYE exchange. `max_attempts` bounds
    /// the retransmits: the daemon and `ping` pass the configured `retries`; a
    /// single-shot `pulse`/`bye` passes 1. The per-attempt CHALLENGE wait follows
    /// the SIP backoff `min(retry_initial · 2^(k-1), retry_max)`, so attempt 1
    /// waits `retry_initial` (T1) and a 1-attempt try is the quick single shot
    /// (not the full T2 window). For `Renew`, the parameter is resolved once
    /// (`param_override`, else `param_command`) and reused; `Release` (BYE)
    /// carries no parameter.
    async fn run_cycle(
        &self,
        max_attempts: u32,
        mode: Mode,
        param_override: Option<&str>,
    ) -> anyhow::Result<()> {
        let param: Option<String> = match (mode, param_override) {
            // An explicit override is validated and used as-is for either mode.
            (_, Some(p)) => {
                validate_param(p, self.target.param_max_len)?;
                Some(p.to_string())
            }
            // A normal pulse falls back to `param_command`; a release with no
            // explicit param carries none.
            (Mode::Renew, None) => self.generate_param().await?,
            (Mode::Release, None) => None,
        };

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(&self.target.server_addr).await?;

        let attempts = max_attempts.max(1);
        for attempt in 1..=attempts {
            // SIP-style backoff: attempt k waits T1·2^(k-1) for the CHALLENGE,
            // capped at T2, before retransmitting.
            let timeout = self
                .target
                .retry_initial
                .saturating_mul(1u32 << (attempt - 1).min(31))
                .min(self.target.retry_max);
            match self
                .attempt_once(&socket, param.as_deref(), timeout, mode)
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(server = %self.target.name, attempt, max = attempts, timeout_ms = timeout.as_millis() as u64, error = %e, "handshake attempt failed")
                }
            }
        }
        anyhow::bail!("all {attempts} handshake attempt(s) failed");
    }

    async fn attempt_once(
        &self,
        socket: &UdpSocket,
        param: Option<&str>,
        timeout: Duration,
        mode: Mode,
    ) -> anyhow::Result<()> {
        let encrypt = self.target.wire_encryption;
        let client_hex = self.client_id.to_hex();

        // 1. Build and sign the HELLO (fresh nonce per attempt).
        let timestamp = now_unix();
        let hello_nonce: [u8; 16] = Nonce::generate().0[..16].try_into().unwrap();
        let hello_payload = hello_signing_payload(
            &self.target.server_id,
            &client_hex,
            timestamp,
            &B64.encode(hello_nonce),
        );
        let hello = Packet::Hello(Hello {
            client_id: self.client_id,
            client_timestamp_unix: timestamp,
            hello_nonce,
            signature: crypto::sign_payload_raw(&self.signing_key, &hello_payload),
        });

        // 2. Send it (sealed if wire encryption is on), keeping the ephemeral
        //    secret so we can open the sealed CHALLENGE reply.
        let (datagram, session_secret) = self.frame_outbound(&hello.encode(), encrypt)?;
        socket.send(&datagram).await?;
        info!(server = %self.target.name, "sent HELLO");

        // 3. Await CHALLENGE (per-attempt SIP backoff timeout).
        let mut buf = vec![0u8; 2048];
        let len = match tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
            Ok(r) => r?,
            Err(_) => anyhow::bail!("timed out waiting for CHALLENGE"),
        };
        let challenge_bytes = self.unframe_inbound(
            &buf[..len],
            encrypt,
            session_secret.as_deref(),
            &hello_nonce,
        )?;
        let challenge = match Packet::decode(&challenge_bytes)? {
            Packet::Challenge(c) => c,
            other => anyhow::bail!("expected CHALLENGE, got {other:?}"),
        };
        if challenge.client_id != self.client_id {
            anyhow::bail!("challenge client_id mismatch");
        }
        info!(server = %self.target.name, expires_at = challenge.expires_at_unix, "received CHALLENGE");

        // 4. Seal the optional parameter (shared by RESPONSE and BYE — both carry
        //    one) and advertise our pulse interval so the server can size the
        //    access lease. Both are covered by the signature (encrypt-then-sign).
        let param_blob = match param {
            Some(p) => Some(self.seal_param(p)?),
            None => None,
        };
        let param_b64 = param_blob
            .as_ref()
            .map(|b| B64.encode(b))
            .unwrap_or_default();
        let interval_seconds = self.target.interval.as_secs().min(u32::MAX as u64) as u32;
        let nonce_b64 = B64.encode(challenge.nonce);

        // 5. Build the final signed packet. A RESPONSE renews the lease; a BYE
        //    releases it. Same fields, but a distinct signing payload (`:bye` vs
        //    `:response`) so neither can be replayed/re-framed as the other.
        let (packet, kind) = match mode {
            Mode::Renew => {
                let payload = response_signing_payload(
                    &self.target.server_id,
                    &client_hex,
                    &nonce_b64,
                    interval_seconds,
                    challenge.expires_at_unix,
                    &param_b64,
                );
                let response = Packet::Response(Response {
                    client_id: self.client_id,
                    nonce: challenge.nonce,
                    interval_seconds,
                    param: param_blob,
                    signature: crypto::sign_payload_raw(&self.signing_key, &payload),
                });
                (response, "RESPONSE")
            }
            Mode::Release => {
                let payload = bye_signing_payload(
                    &self.target.server_id,
                    &client_hex,
                    &nonce_b64,
                    interval_seconds,
                    challenge.expires_at_unix,
                    &param_b64,
                );
                let bye = Packet::Bye(Bye {
                    client_id: self.client_id,
                    nonce: challenge.nonce,
                    interval_seconds,
                    param: param_blob,
                    signature: crypto::sign_payload_raw(&self.signing_key, &payload),
                });
                (bye, "BYE")
            }
        };

        // 6. Send it (sealed if encrypting). No reply expected.
        let (datagram, _) = self.frame_outbound(&packet.encode(), encrypt)?;
        socket.send(&datagram).await?;
        info!(server = %self.target.name, "sent {kind}");
        Ok(())
    }

    /// Frame an outbound packet: seal it to the server (returning the ephemeral
    /// secret so a sealed reply can be opened) or pass it through in the clear.
    fn frame_outbound(
        &self,
        packet_bytes: &[u8],
        encrypt: bool,
    ) -> anyhow::Result<(Vec<u8>, Option<Zeroizing<X25519Bytes>>)> {
        if !encrypt {
            return Ok((packet_bytes.to_vec(), None));
        }
        let server_pub = self
            .target
            .server_pub
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("wire encryption requires server_encryption_key"))?;
        let (blob, eph_secret) = crypto::seal(server_pub, packet_bytes, crypto::CTX_WIRE)?;
        // Wrap the ephemeral secret so it is wiped from memory on drop.
        Ok((blob, Some(Zeroizing::new(eph_secret))))
    }

    /// Recover an inbound packet's cleartext bytes by opening the
    /// server-authenticated reply with our ephemeral secret and the pinned
    /// server public key (or passing through in cleartext mode). Opening
    /// succeeding proves the CHALLENGE came from the real server.
    fn unframe_inbound(
        &self,
        datagram: &[u8],
        encrypt: bool,
        session_secret: Option<&X25519Bytes>,
        bind: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        if !encrypt {
            return Ok(datagram.to_vec());
        }
        let secret = session_secret.ok_or_else(|| anyhow::anyhow!("missing session secret"))?;
        let server_pub = self
            .target
            .server_pub
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("wire encryption requires server_encryption_key"))?;
        crypto::open_reply(secret, server_pub, datagram, bind).map_err(|_| {
            anyhow::anyhow!("CHALLENGE failed to authenticate as the configured server")
        })
    }

    /// Seal a parameter plaintext to the server's X25519 key (raw blob bytes).
    fn seal_param(&self, plaintext: &str) -> anyhow::Result<Vec<u8>> {
        let server_pub = self
            .target
            .server_pub
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("param requires server_encryption_key"))?;
        let (blob, _) = crypto::seal(server_pub, plaintext.as_bytes(), crypto::CTX_PARAM)?;
        Ok(blob)
    }

    /// Run the configured `param_command` and return its validated stdout.
    async fn generate_param(&self) -> anyhow::Result<Option<String>> {
        let argv = match &self.target.param_command {
            Some(a) => a,
            None => return Ok(None),
        };

        let mut cmd = tokio::process::Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let child = cmd
            .spawn()
            .map_err(|e| anyhow::anyhow!("param_command failed to spawn: {e}"))?;

        let output =
            match tokio::time::timeout(self.target.param_command_timeout, child.wait_with_output())
                .await
            {
                Ok(r) => r.map_err(|e| anyhow::anyhow!("param_command error: {e}"))?,
                Err(_) => anyhow::bail!("param_command timed out"),
            };
        if !output.status.success() {
            anyhow::bail!("param_command exited with {}", output.status);
        }

        let text = String::from_utf8(output.stdout)
            .map_err(|_| anyhow::anyhow!("param_command output is not UTF-8"))?;
        let trimmed = text.trim();
        validate_param(trimmed, self.target.param_max_len)?;
        Ok(Some(trimmed.to_string()))
    }
}

/// Validate a parameter value before sending: bounded length and no control
/// characters (it ends up in hook argv, logs, and `status`). Used for both the
/// `param_command` output and an ad-hoc `--param` override.
fn validate_param(value: &str, max_len: usize) -> anyhow::Result<()> {
    if value.len() > max_len {
        anyhow::bail!(
            "param ({} bytes) exceeds param_max_len {}",
            value.len(),
            max_len
        );
    }
    if value.chars().any(|c| c.is_control()) {
        anyhow::bail!("param contains control characters");
    }
    Ok(())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
