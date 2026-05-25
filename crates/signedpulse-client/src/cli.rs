//! CLI entry point for the SignedPulse client (`run_cli`), invoked by the
//! `signedpulse-client` binary in the `signedpulse` umbrella crate.

use std::path::PathBuf;

use crate::client::Client;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clap::{Parser, Subcommand};
use signedpulse_common::config::ClientConfig;
use signedpulse_common::crypto;
use signedpulse_common::protocol::ClientId;
use signedpulse_common::service::{self, ServiceSpec, ServiceTarget};
use signedpulse_common::status::{self, ClientStatusSnapshot};

#[derive(Parser, Debug)]
#[command(
    name = "signedpulse-client",
    about = "Periodically proves the client's real UDP source IP to a SignedPulse server",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to the client TOML config file (used by `run` and `install-service`).
    #[arg(long, default_value = "/etc/signedpulse/client.toml", global = true)]
    config: PathBuf,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a config and keypair, then print what to add on the server.
    Init(InitArgs),
    /// Add another server to pulse, appended to an existing client config.
    AddServer(AddServerArgs),
    /// Send a single pulse to each configured server and exit (no retry).
    Pulse,
    /// Like `pulse`, but retry (SIP backoff) if no reply is received.
    Ping,
    /// Generate a new Ed25519 keypair and print the config snippets.
    GenerateKey,
    /// Install (and start) this client as a background service.
    InstallService(InstallArgs),
    /// Show live status of the running client (local-only).
    Status,
}

#[derive(clap::Args, Debug)]
struct InitArgs {
    /// Server address, e.g. "203.0.113.10" or "203.0.113.10:7370".
    #[arg(long)]
    server: String,
    /// Server's base64 X25519 public key (printed by `signedpulse-server init`).
    /// Required for the default encrypted mode.
    #[arg(long)]
    server_key: Option<String>,
    /// 256-bit client id (64 hex). Defaults to a freshly generated random id.
    #[arg(long)]
    client_id: Option<String>,
    /// Optional human-friendly label for server logs/status.
    #[arg(long)]
    label: Option<String>,
    /// Must match the server's server_id.
    #[arg(long, default_value = "signedpulse-main")]
    server_id: String,
    /// Seconds between pulses.
    #[arg(long, default_value_t = 300)]
    interval: u64,
    /// Send cleartext binary instead of sealed datagrams (not recommended).
    #[arg(long)]
    no_encryption: bool,
    /// Overwrite an existing config file.
    #[arg(long)]
    force: bool,
}

#[derive(clap::Args, Debug)]
struct AddServerArgs {
    /// Local label for this server: the `[client.servers.<name>]` key, used for
    /// status. Must be unique (not the primary's, nor an already-added one).
    #[arg(long)]
    name: String,
    /// Server address, e.g. "203.0.113.20" or "203.0.113.20:7370".
    #[arg(long)]
    server: String,
    /// The new server's base64 X25519 public key (printed by its `init`).
    /// Required for the default encrypted mode.
    #[arg(long)]
    server_key: Option<String>,
    /// The remote server's server_id (signed into the payload; must match what
    /// that server is configured with). Defaults to --name when omitted — set it
    /// only when the label differs from the remote id (e.g. two servers that both
    /// use the default `signedpulse-main`).
    #[arg(long)]
    server_id: Option<String>,
    /// Override the pulse interval for this server (else inherits `[client]`).
    #[arg(long)]
    interval: Option<u64>,
    /// This server speaks cleartext binary instead of sealed datagrams.
    #[arg(long)]
    no_encryption: bool,
}

#[derive(clap::Args, Debug)]
struct InstallArgs {
    /// Install a per-user systemd unit instead of a system-wide one (Linux).
    #[arg(long)]
    user: bool,
    /// Only print the service definition; do not write or start anything.
    #[arg(long)]
    print: bool,
}

const DEFAULT_PORT: u16 = 7370;

pub async fn run_cli() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Init(args)) => init(args, &cli.config),
        Some(Command::AddServer(args)) => add_server(args, &cli.config),
        Some(Command::Pulse) => {
            // One-shot, no retry. No logging subscriber, so the handshake's
            // info/warn are silent and run_once prints clean per-server lines.
            let config = ClientConfig::load(&cli.config)?;
            Client::from_config(config)?.run_once(false).await
        }
        Some(Command::Ping) => {
            let config = ClientConfig::load(&cli.config)?;
            Client::from_config(config)?.run_once(true).await
        }
        Some(Command::GenerateKey) => {
            generate_key();
            Ok(())
        }
        Some(Command::InstallService(args)) => install_service(args, &cli.config),
        Some(Command::Status) => status(&cli.config),
        None => {
            init_logging();
            let config = ClientConfig::load(&cli.config)?;
            let client = Client::from_config(config)?;
            client.run_forever().await
        }
    }
}

fn status(config_path: &std::path::Path) -> anyhow::Result<()> {
    let config = ClientConfig::load(config_path)?;

    let (svc_state, svc_how) =
        service::query_service("signedpulse-client", "com.signedpulse.client");
    println!(
        "service:    {} [{svc_how}]",
        status::service_word(svc_state)
    );
    let extra = config.client.servers.len();
    let server_summary = if extra > 0 {
        format!("{} (+{extra} more)", config.client.server_addr)
    } else {
        config.client.server_addr.clone()
    };
    println!(
        "config:     {}  client_id={}  server={}",
        config_path.display(),
        config.client.client_id,
        server_summary
    );

    let snapshot: Option<ClientStatusSnapshot> =
        status::refresh_and_read_component("client", config.client.state_file.as_deref());
    match snapshot {
        None => {
            println!(
                "status:     no live data (client not running, or could not refresh state file)"
            );
        }
        Some(s) => {
            println!(
                "pid:        {}   uptime: {}",
                s.pid,
                status::duration_words(status::now_unix().saturating_sub(s.started_at_unix))
            );
            // One block per server the client pulses, keyed by its local label.
            for (name, leg) in &s.servers {
                if !leg.server_id.is_empty() && leg.server_id != *name {
                    println!(
                        "server {name} (server_id={}, {}):",
                        leg.server_id, leg.server_addr
                    );
                } else {
                    println!("server {name} ({}):", leg.server_addr);
                }
                match leg.last_success_at_unix {
                    Some(t) => println!("  last pulse: OK  {}", status::ago(t)),
                    None => println!("  last pulse: none succeeded yet"),
                }
                // Next pulse ≈ last attempt + interval.
                if let Some(attempt) = leg.last_attempt_at_unix {
                    let next_in = (attempt as i128 + leg.interval_seconds as i128
                        - status::now_unix() as i128)
                        .clamp(i64::MIN as i128, i64::MAX as i128)
                        as i64;
                    if next_in > 0 {
                        println!("  next pulse: in ~{}", status::duration_words(next_in));
                    } else {
                        println!("  next pulse: due now");
                    }
                }
                println!("  last result: {}", leg.last_result);
            }
        }
    }
    Ok(())
}

fn init(args: InitArgs, config_path: &std::path::Path) -> anyhow::Result<()> {
    if config_path.exists() && !args.force {
        anyhow::bail!(
            "config {} already exists; pass --force to overwrite",
            config_path.display()
        );
    }

    let wire_encryption = !args.no_encryption;
    if wire_encryption && args.server_key.is_none() {
        anyhow::bail!(
            "encrypted mode (default) needs --server-key (run `signedpulse-server init` to print \
             it), or pass --no-encryption"
        );
    }

    // These are written verbatim into the TOML config; reject break-out chars.
    validate_token("--server-id", &args.server_id)?;
    if let Some(label) = &args.label {
        validate_token("--label", label)?;
    }

    // A fresh random 256-bit client id unless the caller supplied one.
    let client_id = match args.client_id {
        Some(id) => {
            ClientId::from_hex(&id).map_err(|_| anyhow::anyhow!("--client-id must be 64 hex"))?;
            id
        }
        None => ClientId(crypto::Nonce::generate().0).to_hex(),
    };
    let server_addr = normalize_addr(&args.server);
    validate_addr(&server_addr)?;
    let keys = crypto::generate_keypair();

    let mut config = format!(
        "# Generated by `signedpulse-client init`.\n\
         [client]\n\
         client_id = \"{client_id}\"\n\
         server_addr = \"{server_addr}\"\n\
         server_id = \"{server_id}\"\n\
         interval_seconds = {interval}\n\
         private_key = \"{private_key}\"\n\
         retry_initial_ms = 500\n\
         retry_max_ms = 4000\n\
         retries = 3\n\
         wire_encryption = {wire_encryption}\n",
        client_id = client_id,
        server_addr = server_addr,
        server_id = args.server_id,
        interval = args.interval,
        private_key = keys.private_key_b64,
        wire_encryption = wire_encryption,
    );
    if let Some(key) = &args.server_key {
        config.push_str(&format!("server_encryption_key = \"{key}\"\n"));
    }

    service::write_config_file(config_path, &config, true).map_err(|e| {
        anyhow::anyhow!(
            "failed to write {} ({e}). If this is a system path, re-run with sudo.",
            config_path.display()
        )
    })?;

    let label_arg = args
        .label
        .as_ref()
        .map(|l| format!(" --label \"{l}\""))
        .unwrap_or_default();

    println!(
        "Wrote client config to {} (mode 0600).",
        config_path.display()
    );
    println!();
    println!("=== Do this on the SERVER to authorize this client ===");
    println!();
    println!("Run:");
    println!(
        "  signedpulse-server add-client --client-id \"{}\" --public-key \"{}\"{}",
        client_id, keys.public_key_b64, label_arg
    );
    println!();
    println!("…or add this block to the server's config manually:");
    println!();
    println!("  [[clients]]");
    println!("  client_id = \"{client_id}\"");
    println!("  public_key = \"{}\"", keys.public_key_b64);
    if let Some(l) = &args.label {
        println!("  label = \"{l}\"");
    }
    println!();
    println!("Then start this client (or run `signedpulse-client install-service`).");
    Ok(())
}

fn add_server(args: AddServerArgs, config_path: &std::path::Path) -> anyhow::Result<()> {
    // The config must already exist (with a primary [client] server).
    let existing = ClientConfig::load(config_path).map_err(|e| {
        anyhow::anyhow!(
            "cannot load {} ({e}); run `signedpulse-client init` first",
            config_path.display()
        )
    })?;

    // The label becomes the TOML table key; keep it a safe bare identifier.
    let name = args.name.as_str();
    validate_token("--name", name)?;
    if name == existing.client.server_id {
        anyhow::bail!("--name {name:?} collides with the primary [client] server_id; pick another");
    }
    if existing.client.servers.contains_key(name) {
        anyhow::bail!("server {name:?} is already configured");
    }
    // The wire server_id defaults to the label, but can differ (it must match the
    // remote server's configured server_id). Validate it: it is written verbatim
    // into a TOML string, so it must not be able to break out of it.
    let server_id = args.server_id.as_deref().unwrap_or(name);
    validate_token("--server-id", server_id)?;

    let wire_encryption = !args.no_encryption;
    if wire_encryption && args.server_key.is_none() {
        anyhow::bail!(
            "encrypted mode (default) needs --server-key (run the new server's `init` to print \
             it), or pass --no-encryption"
        );
    }
    if let Some(key) = &args.server_key {
        crypto::x25519_from_base64(key)
            .map_err(|e| anyhow::anyhow!("invalid --server-key: {e}"))?;
    }
    let server_addr = normalize_addr(&args.server);
    // Written verbatim into a TOML string; reject anything that could break out.
    validate_addr(&server_addr)?;

    // Append a `[client.servers.<name>]` table at EOF (always valid TOML; leaves
    // existing content intact). Quote the key if it isn't a bare TOML key.
    let mut block = format!(
        "\n[client.servers.{}]\nserver_addr = \"{server_addr}\"\n",
        toml_table_key(name)
    );
    // Only write server_id when it differs from the label (else it's implied).
    if server_id != name {
        block.push_str(&format!("server_id = \"{server_id}\"\n"));
    }
    if let Some(key) = &args.server_key {
        block.push_str(&format!("server_encryption_key = \"{key}\"\n"));
    }
    if !wire_encryption {
        block.push_str("wire_encryption = false\n");
    }
    if let Some(interval) = args.interval {
        block.push_str(&format!("interval_seconds = {interval}\n"));
    }

    let mut text = std::fs::read_to_string(config_path)?;
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&block);
    // The client config holds the Ed25519 private key, so rewrite it 0600 (and
    // without following a symlink) — std::fs::write would re-create it 0644.
    service::write_config_file(config_path, &text, true)?;

    // Re-load to confirm the file still parses and validates.
    let updated = ClientConfig::load(config_path)?;
    let total = 1 + updated.client.servers.len();
    println!(
        "Added server {name:?} (server_id={server_id:?}, {server_addr}). \
         This client now pulses {total} server(s)."
    );

    // Derive this client's public key so the operator can authorize it there.
    if let Ok(sk) = crypto::load_signing_key(&updated.client.private_key) {
        let public_key_b64 = B64.encode(sk.verifying_key().to_bytes());
        println!();
        println!("Authorize this client on the new server:");
        println!(
            "  signedpulse-server add-client --client-id \"{}\" --public-key \"{}\"",
            updated.client.client_id, public_key_b64
        );
    }
    println!("Then restart this client (e.g. `systemctl restart signedpulse-client`) to apply.");
    Ok(())
}

/// Render a `server_id` as a TOML table-header key: bare when it contains only
/// `[A-Za-z0-9_-]`, otherwise a quoted key. Callers pass `validate_token`-checked
/// values, so this is always the bare branch in practice.
fn toml_table_key(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        s.to_string()
    } else {
        format!("\"{s}\"")
    }
}

/// Validate an identifier-like CLI value (label / server_id). These are written
/// verbatim into TOML basic strings *and* echoed inside shell commands, so we
/// restrict them to a conservative charset that cannot break out of either —
/// no quotes, backslashes, `$`, backticks, whitespace, or control characters.
fn validate_token(field: &str, value: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        anyhow::bail!("{field} must not be empty");
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        anyhow::bail!("{field} may only contain ASCII letters, digits, '-', '_', and '.'");
    }
    Ok(())
}

/// Validate a `host[:port]` value before it is written verbatim into a TOML
/// string. Addresses legitimately contain ':' and '.', so we only forbid what
/// would let it break out of the string (quotes, backslashes, whitespace, control).
fn validate_addr(value: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        anyhow::bail!("--server must not be empty");
    }
    if value
        .chars()
        .any(|c| c == '"' || c == '\\' || c.is_whitespace() || c.is_control())
    {
        anyhow::bail!("--server must not contain quotes, backslashes, or whitespace");
    }
    Ok(())
}

fn install_service(args: InstallArgs, config_path: &std::path::Path) -> anyhow::Result<()> {
    let exec_path = std::env::current_exe()?;
    let spec = ServiceSpec {
        unit_name: "signedpulse-client".into(),
        description: "SignedPulse client".into(),
        exec_path,
        args: vec!["--config".into(), config_path.display().to_string()],
        launchd_label: "com.signedpulse.client".into(),
    };

    // Auto-detect: macOS uses launchd; Linux uses systemd (system or --user).
    let target = if args.user {
        ServiceTarget::SystemdUser
    } else if cfg!(target_os = "macos") {
        ServiceTarget::LaunchdAgent
    } else {
        ServiceTarget::SystemdSystem
    };

    if args.print {
        print!("{}", service::render(&spec, target));
        return Ok(());
    }

    let report = service::install(&spec, target, true).map_err(|e| {
        anyhow::anyhow!("failed to install service ({e}). For a system service, re-run with sudo.")
    })?;
    report_install(&report);
    Ok(())
}

fn report_install(report: &service::InstallReport) {
    println!("Installed service definition at {}.", report.path.display());
    if report.activated {
        println!("Service activated and started.");
    } else {
        if let Some(note) = &report.note {
            println!("{note}");
        }
        for cmd in &report.activation_commands {
            println!("  {cmd}");
        }
    }
}

/// Append the default port if the user gave a bare host/IP.
fn normalize_addr(input: &str) -> String {
    if input.parse::<std::net::SocketAddr>().is_ok() {
        return input.to_string();
    }
    // A bare IPv6 literal would already contain ':'; only add a port when there
    // is no ':' at all (i.e. a hostname or IPv4 without a port).
    if input.contains(':') {
        input.to_string()
    } else {
        format!("{input}:{DEFAULT_PORT}")
    }
}

fn generate_key() {
    let keys = crypto::generate_keypair();
    println!("# SignedPulse Ed25519 keypair");
    println!("# Keep the private key secret. Place it in the CLIENT config:");
    println!();
    println!("[client]");
    println!("private_key = \"{}\"", keys.private_key_b64);
    println!();
    println!("# Place the public key in the SERVER config under the matching client:");
    println!();
    println!("[[clients]]");
    println!("client_id = \"REPLACE_ME\"");
    println!("public_key = \"{}\"", keys.public_key_b64);
}

fn init_logging() {
    use std::io::IsTerminal;
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // Only colorize on a real terminal. Under systemd/journald (or any redirect)
    // stderr is not a TTY, so ANSI codes would otherwise land as `#033[..m`
    // garbage in the journal/syslog. There, also drop our timestamp since the
    // log daemon already stamps every line.
    let ansi = std::io::stderr().is_terminal();
    let builder = fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(ansi);
    if ansi {
        builder.init();
    } else {
        builder.without_time().init();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_addr_adds_default_port() {
        assert_eq!(normalize_addr("203.0.113.10"), "203.0.113.10:7370");
        assert_eq!(normalize_addr("example.com"), "example.com:7370");
    }

    #[test]
    fn normalize_addr_keeps_explicit_port() {
        assert_eq!(normalize_addr("203.0.113.10:9999"), "203.0.113.10:9999");
        assert_eq!(normalize_addr("example.com:5000"), "example.com:5000");
    }

    #[test]
    fn validate_token_rejects_toml_and_shell_breakouts() {
        assert!(validate_token("--server-id", "signedpulse-main").is_ok());
        assert!(validate_token("--server-id", "sp_B.2").is_ok());
        assert!(validate_token("--server-id", "").is_err());
        // Quote/newline would break out of a TOML string; $/backtick are shell-active.
        assert!(validate_token("--server-id", "x\"\nprivate_key = \"y").is_err());
        assert!(validate_token("--server-id", "$(reboot)").is_err());
        assert!(validate_token("--server-id", "a`b`").is_err());
        assert!(validate_token("--server-id", "has space").is_err());
    }

    #[test]
    fn validate_addr_rejects_string_breakouts() {
        assert!(validate_addr("203.0.113.20:7370").is_ok());
        assert!(validate_addr("example.com:7370").is_ok());
        assert!(validate_addr("[2001:db8::1]:7370").is_ok());
        assert!(validate_addr("x\":1\"\nprivate_key = \"y").is_err());
        assert!(validate_addr("has space:1").is_err());
        assert!(validate_addr("").is_err());
    }

    #[test]
    fn toml_table_key_quotes_only_when_needed() {
        assert_eq!(toml_table_key("signedpulse-backup"), "signedpulse-backup");
        assert_eq!(toml_table_key("sp_B2"), "sp_B2");
        // A dot isn't a bare-key character, so it must be quoted.
        assert_eq!(toml_table_key("a.b"), "\"a.b\"");
    }
}
