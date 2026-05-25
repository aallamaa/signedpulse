//! End-to-end integration tests over the binary protocol, in both cleartext and
//! full-packet-encryption modes. A raw client socket drives
//! HELLO → CHALLENGE → RESPONSE (building/parsing binary frames and
//! sealing/opening envelopes with a test-held server X25519 key), a mock command
//! executor captures the decrypted param + source IP, and we verify replay
//! rejection, param length limits, and that the server stays silent to probes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use signedpulse_common::config::ServerConfig;
use signedpulse_common::crypto::{self, X25519Bytes};
use signedpulse_common::protocol::{
    hello_signing_payload, response_signing_payload, ClientId, Hello, Packet, Response,
};
use signedpulse_server::server::Server;
use signedpulse_server::testing::MockCommandExecutor;
use tokio::net::UdpSocket;

const SERVER_ID: &str = "signedpulse-main";

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

struct Fixture {
    addr: SocketAddr,
    mock: MockCommandExecutor,
    revoke: MockCommandExecutor,
    server: Arc<Server>,
    client_id: ClientId,
    signing_key: ed25519_dalek::SigningKey,
    server_pub: X25519Bytes,
    encrypt: bool,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

/// The pulse interval the test client advertises in its RESPONSE.
const TEST_INTERVAL_SECS: u32 = 1;

/// Build a server with one authorized client and spawn it on an ephemeral port.
async fn fixture(encrypt: bool, max_param_len: usize, state_file: Option<&str>) -> Fixture {
    let client_id = ClientId([7u8; 32]);
    let ed = crypto::generate_keypair();
    let signing_key = crypto::load_signing_key(&ed.private_key_b64).unwrap();
    let (enc_secret, enc_public) = crypto::generate_encryption_keypair();
    let server_pub = crypto::x25519_from_base64(&enc_public).unwrap();

    let wire = if encrypt { "required" } else { "off" };
    let state_line = state_file
        .map(|p| format!("state_file = \"{p}\"\n"))
        .unwrap_or_default();
    let toml = format!(
        r#"
        [server]
        bind = "127.0.0.1:0"
        server_id = "{SERVER_ID}"
        nonce_ttl_seconds = 30
        max_param_len = {max_param_len}
        wire_encryption = "{wire}"
        encryption_private_key = "{enc_secret}"
        lease_max_seconds = 1
        {state_line}
        [command]
        argv = ["/bin/true", "{{ip}}", "{{client_id}}", "{{param}}", "{{new}}"]
        max_concurrent = 4

        [[clients]]
        client_id = "{client_hex}"
        public_key = "{pubkey}"
        label = "tester"
        "#,
        client_hex = client_id.to_hex(),
        pubkey = ed.public_key_b64,
    );
    let config: ServerConfig = toml::from_str(&toml).expect("config parses");

    let mock = MockCommandExecutor::new();
    let revoke = MockCommandExecutor::new();
    let server = Arc::new(
        Server::from_config(
            config,
            Arc::new(mock.clone()),
            Some(Arc::new(revoke.clone())),
        )
        .unwrap(),
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let run_server = server.clone();
    tokio::spawn(async move {
        run_server
            .run(socket, async move {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });

    Fixture {
        addr,
        mock,
        revoke,
        server,
        client_id,
        signing_key,
        server_pub,
        encrypt,
        _shutdown: tx,
    }
}

impl Fixture {
    /// Seal `bytes` to the server if encrypting; keep the ephemeral secret so the
    /// reply can be opened.
    fn frame(&self, bytes: &[u8]) -> (Vec<u8>, Option<X25519Bytes>) {
        if self.encrypt {
            let (blob, eph) = crypto::seal(&self.server_pub, bytes, crypto::CTX_WIRE).unwrap();
            (blob, Some(eph))
        } else {
            (bytes.to_vec(), None)
        }
    }

    /// Open the server-authenticated CHALLENGE reply with our ephemeral secret
    /// and the pinned server public key.
    fn unframe(&self, datagram: &[u8], eph: Option<&X25519Bytes>, bind: &[u8]) -> Vec<u8> {
        if self.encrypt {
            crypto::open_reply(eph.unwrap(), &self.server_pub, datagram, bind).unwrap()
        } else {
            datagram.to_vec()
        }
    }

    /// Run a full handshake; return the exact RESPONSE datagram bytes (for replay).
    async fn handshake(&self, sock: &UdpSocket, param: Option<&str>) -> Vec<u8> {
        let client_hex = self.client_id.to_hex();

        // HELLO
        let ts = now_unix();
        let hello_nonce: [u8; 16] = crypto::Nonce::generate().0[..16].try_into().unwrap();
        let hp = hello_signing_payload(SERVER_ID, &client_hex, ts, &B64.encode(hello_nonce));
        let hello = Packet::Hello(Hello {
            client_id: self.client_id,
            client_timestamp_unix: ts,
            hello_nonce,
            signature: crypto::sign_payload_raw(&self.signing_key, &hp),
        });
        let (datagram, eph) = self.frame(&hello.encode());
        sock.send_to(&datagram, self.addr).await.unwrap();

        // CHALLENGE
        let mut buf = vec![0u8; 4096];
        let len = tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf))
            .await
            .expect("challenge timed out")
            .unwrap();
        let challenge =
            match Packet::decode(&self.unframe(&buf[..len], eph.as_ref(), &hello_nonce)).unwrap() {
                Packet::Challenge(c) => c,
                other => panic!("expected challenge, got {other:?}"),
            };

        // RESPONSE
        let param_blob = param.map(|p| {
            crypto::seal(&self.server_pub, p.as_bytes(), crypto::CTX_PARAM)
                .unwrap()
                .0
        });
        let param_b64 = param_blob
            .as_ref()
            .map(|b| B64.encode(b))
            .unwrap_or_default();
        let rp = response_signing_payload(
            SERVER_ID,
            &client_hex,
            &B64.encode(challenge.nonce),
            TEST_INTERVAL_SECS,
            challenge.expires_at_unix,
            &param_b64,
        );
        let response = Packet::Response(Response {
            client_id: self.client_id,
            nonce: challenge.nonce,
            interval_seconds: TEST_INTERVAL_SECS,
            param: param_blob,
            signature: crypto::sign_payload_raw(&self.signing_key, &rp),
        });
        let (datagram, _) = self.frame(&response.encode());
        sock.send_to(&datagram, self.addr).await.unwrap();
        datagram
    }
}

async fn recv_timeout(sock: &UdpSocket) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(Duration::from_millis(400), sock.recv(&mut buf)).await {
        Ok(Ok(n)) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

async fn wait_for<F: Fn() -> bool>(cond: F) {
    for _ in 0..50 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("condition not met within deadline");
}

#[tokio::test]
async fn encrypted_handshake_with_param_then_replay_rejected() {
    let fx = fixture(true, 256, None).await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = sock.local_addr().unwrap();

    let response = fx.handshake(&sock, Some("deploy-v1.4.2")).await;
    wait_for(|| fx.mock.count() >= 1).await;

    let execs = fx.mock.executions();
    assert_eq!(execs.len(), 1);
    assert_eq!(execs[0].source_ip, local.ip());
    assert_eq!(execs[0].source_port, local.port());
    assert_eq!(execs[0].param.as_deref(), Some("deploy-v1.4.2"));

    // Replaying the identical RESPONSE datagram must not run the hook again.
    sock.send_to(&response, fx.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(fx.mock.count(), 1, "replayed RESPONSE must not re-execute");
}

#[tokio::test]
async fn cleartext_handshake_executes_without_param() {
    let fx = fixture(false, 256, None).await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = sock.local_addr().unwrap();

    fx.handshake(&sock, None).await;
    wait_for(|| fx.mock.count() >= 1).await;

    let execs = fx.mock.executions();
    assert_eq!(execs.len(), 1);
    assert_eq!(execs[0].source_ip, local.ip());
    assert_eq!(execs[0].param, None);
}

#[tokio::test]
async fn over_length_param_is_rejected() {
    // max_param_len = 4, but we send 13 bytes of plaintext.
    let fx = fixture(true, 4, None).await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    fx.handshake(&sock, Some("deploy-v1.4.2")).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        fx.mock.count(),
        0,
        "over-length param must not execute the hook"
    );
}

#[tokio::test]
async fn server_is_silent_to_probes() {
    // In encrypted mode every probe fails to open and must get no reply.
    let fx = fixture(true, 256, None).await;
    let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    for junk in [
        b"not a packet".to_vec(),
        vec![0u8; 80], // wrong size / undecryptable
        crypto::Nonce::generate().0.to_vec(),
    ] {
        probe.send_to(&junk, fx.addr).await.unwrap();
    }
    assert!(
        recv_timeout(&probe).await.is_none(),
        "server must stay silent to probes"
    );
}

#[tokio::test]
async fn status_snapshot_reflects_verified_pulse() {
    use signedpulse_common::status::{self, ServerStatusSnapshot};

    let state_path = std::env::temp_dir().join(format!(
        "signedpulse-it-{}-{}.state.json",
        std::process::id(),
        now_unix()
    ));
    let fx = fixture(true, 256, Some(&state_path.display().to_string())).await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = sock.local_addr().unwrap();

    fx.handshake(&sock, Some("hello-world")).await;
    wait_for(|| fx.mock.count() >= 1).await;

    fx.server.write_status();
    let snap: ServerStatusSnapshot = status::read_snapshot(&state_path).expect("status file");
    assert!(snap.verified >= 1);
    let pulse = snap.last_pulse.expect("last_pulse");
    assert_eq!(pulse.source_ip, local.ip());
    assert_eq!(pulse.source_port, local.port());
    let hook = snap.last_hook.expect("last_hook");
    assert_eq!(hook.param.as_deref(), Some("hello-world"));
    assert_eq!(hook.client_id, "tester");

    let _ = std::fs::remove_file(&state_path);
}

#[tokio::test]
async fn lease_grants_marks_new_then_revokes_on_expiry() {
    let fx = fixture(true, 256, None).await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = sock.local_addr().unwrap();

    // First pulse: grant hook fires, flagged as a new session.
    fx.handshake(&sock, None).await;
    wait_for(|| fx.mock.count() >= 1).await;
    let grant = fx.mock.executions();
    assert_eq!(grant[0].source_ip, local.ip());
    assert!(grant[0].is_new, "first pulse must be flagged new");
    assert_eq!(fx.revoke.count(), 0, "no revoke before expiry");

    // lease_max_seconds = 1, so the lease expires shortly; a forced scan then
    // runs the revoke hook for that IP (hex client id, not the label).
    tokio::time::sleep(Duration::from_millis(1200)).await;
    fx.server.run_lease_scan();
    wait_for(|| fx.revoke.count() >= 1).await;
    let revoked = fx.revoke.executions();
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].source_ip, local.ip());
    assert_eq!(revoked[0].client_id, fx.client_id.to_hex());
    assert!(!revoked[0].is_new, "revoke is not a new session");
}
