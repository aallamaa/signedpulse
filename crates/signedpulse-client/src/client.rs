//! The client side of the handshake and the periodic run loop.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use signedpulse_common::config::ClientConfig;
use signedpulse_common::crypto::{self, Nonce, X25519Bytes};
use signedpulse_common::protocol::{
    hello_signing_payload, response_signing_payload, ClientId, Hello, Packet, Response,
};
use signedpulse_common::status::{self, ClientStatusSnapshot};
use tokio::net::UdpSocket;
use tracing::{info, warn};
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

/// Holds the resolved client configuration and the loaded keys.
pub struct Client {
    config: ClientConfig,
    signing_key: SigningKey,
    client_id: ClientId,
    /// Server X25519 public key (for wire and param encryption), if configured.
    server_pub: Option<X25519Bytes>,
    status: Arc<Mutex<ClientStatusSnapshot>>,
    state_path: PathBuf,
}

impl Client {
    pub fn from_config(config: ClientConfig) -> anyhow::Result<Self> {
        let signing_key = crypto::load_signing_key(&config.client.private_key)
            .map_err(|e| anyhow::anyhow!("invalid private_key in client config: {e}"))?;
        let client_id = ClientId::from_hex(&config.client.client_id)
            .map_err(|_| anyhow::anyhow!("client.client_id must be 64 hex characters"))?;
        let server_pub = match &config.client.server_encryption_key {
            Some(b64) => Some(
                crypto::x25519_from_base64(b64)
                    .map_err(|e| anyhow::anyhow!("invalid server_encryption_key: {e}"))?,
            ),
            None => None,
        };
        if config.client.wire_encryption && server_pub.is_none() {
            anyhow::bail!("wire_encryption is on but server_encryption_key is missing");
        }
        let state_path = config
            .client
            .state_file
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| status::default_state_path("client"));
        let status = Arc::new(Mutex::new(ClientStatusSnapshot {
            started_at_unix: now_unix(),
            pid: std::process::id(),
            server_addr: config.client.server_addr.clone(),
            interval_seconds: config.client.interval_seconds,
            last_result: "pending".to_string(),
            ..Default::default()
        }));
        Ok(Client {
            config,
            signing_key,
            client_id,
            server_pub,
            status,
            state_path,
        })
    }

    /// Serialize the current live status to the state file. Errors are logged.
    fn write_status(&self) {
        let snapshot = self.status.lock().unwrap().clone();
        if let Err(e) = status::write_snapshot(&self.state_path, &snapshot) {
            warn!(path = %self.state_path.display(), error = %e, "failed to write status file");
        }
    }

    /// Run forever: every `interval_seconds`, perform one handshake cycle.
    pub async fn run_forever(&self) -> anyhow::Result<()> {
        let interval = Duration::from_secs(self.config.client.interval_seconds);
        info!(
            client_id = %self.config.client.client_id,
            server = %self.config.client.server_addr,
            interval_s = self.config.client.interval_seconds,
            wire_encryption = self.config.client.wire_encryption,
            "signedpulse client started"
        );

        let pid_path = status::pid_path(&self.state_path);
        if let Err(e) = status::write_pidfile(&pid_path) {
            warn!(path = %pid_path.display(), error = %e, "failed to write pid file");
        }
        let mut dump = DumpListener::new()?;

        loop {
            let now = now_unix();
            let result = self.run_cycle().await;
            {
                let mut s = self.status.lock().unwrap();
                s.last_attempt_at_unix = Some(now);
                match &result {
                    Ok(()) => {
                        s.last_success_at_unix = Some(now);
                        s.last_result = "ok".to_string();
                    }
                    Err(e) => s.last_result = e.to_string(),
                }
            }
            if let Err(e) = result {
                warn!(error = %e, "pulse cycle failed");
            }

            // Wait for the next interval, but answer status-dump requests promptly.
            let sleep = tokio::time::sleep(interval);
            tokio::pin!(sleep);
            loop {
                tokio::select! {
                    _ = &mut sleep => break,
                    _ = dump.recv() => self.write_status(),
                }
            }
        }
    }

    /// One full HELLO → CHALLENGE → RESPONSE exchange, with retries on packet
    /// loss. The parameter is generated once per cycle and reused across retries.
    pub async fn run_cycle(&self) -> anyhow::Result<()> {
        let param = self.generate_param().await?;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(&self.config.client.server_addr).await?;

        let timeout = Duration::from_secs(self.config.client.challenge_timeout_seconds);
        let retries = self.config.client.retries;

        for attempt in 1..=retries.max(1) {
            match self.attempt_once(&socket, timeout, param.as_deref()).await {
                Ok(()) => return Ok(()),
                Err(e) => warn!(attempt, max = retries, error = %e, "handshake attempt failed"),
            }
        }
        anyhow::bail!("all {} handshake attempts failed", retries.max(1));
    }

    async fn attempt_once(
        &self,
        socket: &UdpSocket,
        timeout: Duration,
        param: Option<&str>,
    ) -> anyhow::Result<()> {
        let encrypt = self.config.client.wire_encryption;
        let client_hex = self.client_id.to_hex();

        // 1. Build and sign the HELLO (fresh nonce per attempt).
        let timestamp = now_unix();
        let hello_nonce: [u8; 16] = Nonce::generate().0[..16].try_into().unwrap();
        let hello_payload = hello_signing_payload(
            &self.config.client.server_id,
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
        info!("sent HELLO");

        // 3. Await CHALLENGE.
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
        info!(expires_at = challenge.expires_at_unix, "received CHALLENGE");

        // 4. Seal the optional parameter and build the signed RESPONSE.
        let param_blob = match param {
            Some(p) => Some(self.seal_param(p)?),
            None => None,
        };
        let param_b64 = param_blob
            .as_ref()
            .map(|b| B64.encode(b))
            .unwrap_or_default();
        let payload = response_signing_payload(
            &self.config.client.server_id,
            &client_hex,
            &B64.encode(challenge.nonce),
            challenge.expires_at_unix,
            &param_b64,
        );
        let response = Packet::Response(Response {
            client_id: self.client_id,
            nonce: challenge.nonce,
            param: param_blob,
            signature: crypto::sign_payload_raw(&self.signing_key, &payload),
        });

        // 5. Send the RESPONSE (sealed if encrypting). No reply expected.
        let (datagram, _) = self.frame_outbound(&response.encode(), encrypt)?;
        socket.send(&datagram).await?;
        info!("sent RESPONSE");
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
            .server_pub
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("param requires server_encryption_key"))?;
        let (blob, _) = crypto::seal(server_pub, plaintext.as_bytes(), crypto::CTX_PARAM)?;
        Ok(blob)
    }

    /// Run the configured `param_command` and return its validated stdout.
    async fn generate_param(&self) -> anyhow::Result<Option<String>> {
        let argv = match &self.config.client.param_command {
            Some(a) => a,
            None => return Ok(None),
        };
        let timeout = Duration::from_secs(self.config.client.param_command_timeout_seconds);

        let mut cmd = tokio::process::Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let child = cmd
            .spawn()
            .map_err(|e| anyhow::anyhow!("param_command failed to spawn: {e}"))?;

        let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(r) => r.map_err(|e| anyhow::anyhow!("param_command error: {e}"))?,
            Err(_) => anyhow::bail!("param_command timed out"),
        };
        if !output.status.success() {
            anyhow::bail!("param_command exited with {}", output.status);
        }

        let text = String::from_utf8(output.stdout)
            .map_err(|_| anyhow::anyhow!("param_command output is not UTF-8"))?;
        let trimmed = text.trim();
        if trimmed.len() > self.config.client.param_max_len {
            anyhow::bail!(
                "param ({} bytes) exceeds param_max_len {}",
                trimmed.len(),
                self.config.client.param_max_len
            );
        }
        if trimmed.chars().any(|c| c.is_control()) {
            anyhow::bail!("param contains control characters");
        }
        Ok(Some(trimmed.to_string()))
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
