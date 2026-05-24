//! Workspace automation, invoked as `cargo deploy` (see `.cargo/config.toml`).
//!
//! `cargo deploy` builds the release binaries and installs them. It deliberately
//! replaces the manual `cargo build --release` + `sudo install -m 0755 ...` dance.

use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Parser;

const BINARIES: [&str; 2] = ["signedpulse-server", "signedpulse-client"];

#[derive(Parser, Debug)]
#[command(
    name = "cargo-deploy",
    about = "Build and install the SignedPulse binaries"
)]
struct Args {
    /// Install prefix (binaries go in <prefix>/bin).
    #[arg(long, default_value = "/usr/local")]
    prefix: PathBuf,
    /// Override the bin directory (defaults to <prefix>/bin).
    #[arg(long)]
    bindir: Option<PathBuf>,
    /// Staging root prepended to the install path (for packaging).
    #[arg(long, default_value = "")]
    destdir: String,
    /// Skip `cargo build --release` (use already-built binaries).
    #[arg(long)]
    no_build: bool,
    /// Remove the installed binaries instead of installing them.
    #[arg(long)]
    uninstall: bool,
}

fn main() -> anyhow::Result<()> {
    // When run as `cargo deploy`, cargo passes "deploy" as argv[1]; drop it.
    let raw: Vec<String> = std::env::args()
        .enumerate()
        .filter(|(i, a)| !(*i == 1 && a == "deploy"))
        .map(|(_, a)| a)
        .collect();
    let args = Args::parse_from(raw);

    let workspace_root = workspace_root();
    let bindir = join_destdir(
        &args.destdir,
        &args.bindir.unwrap_or_else(|| args.prefix.join("bin")),
    );

    if args.uninstall {
        for bin in BINARIES {
            let path = bindir.join(bin);
            match std::fs::remove_file(&path) {
                Ok(()) => println!("removed {}", path.display()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(permission_hint(e, &path)),
            }
        }
        return Ok(());
    }

    if !args.no_build {
        build_release(&workspace_root)?;
    }

    std::fs::create_dir_all(&bindir).map_err(|e| permission_hint(e, &bindir))?;
    let target_dir = target_dir(&workspace_root);
    for bin in BINARIES {
        let src = target_dir.join("release").join(bin);
        if !src.exists() {
            anyhow::bail!("missing {} — run without --no-build", src.display());
        }
        let dst = bindir.join(bin);
        // Remove any existing target first so we don't write through a symlink
        // planted at the destination, and so a running binary is replaced rather
        // than modified in place.
        match std::fs::remove_file(&dst) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(permission_hint(e, &dst)),
        }
        std::fs::copy(&src, &dst).map_err(|e| permission_hint(e, &dst))?;
        set_executable(&dst)?;
        println!("installed {}", dst.display());
    }
    Ok(())
}

fn build_release(workspace_root: &Path) -> anyhow::Result<()> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(workspace_root)
        .args(["build", "--release"])
        .args(BINARIES.iter().flat_map(|b| ["-p", b]));
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("cargo build --release failed");
    }
    Ok(())
}

/// Workspace root = parent of this crate's manifest dir.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent dir")
        .to_path_buf()
}

fn target_dir(workspace_root: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root.join("target"))
}

/// Prepend a non-empty DESTDIR to an absolute install path.
fn join_destdir(destdir: &str, path: &Path) -> PathBuf {
    if destdir.is_empty() {
        return path.to_path_buf();
    }
    let stripped = path.strip_prefix("/").unwrap_or(path);
    Path::new(destdir).join(stripped)
}

#[cfg(unix)]
fn set_executable(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn permission_hint(e: std::io::Error, path: &Path) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        anyhow::anyhow!(
            "permission denied writing {} — re-run with sudo, or pass --prefix ~/.local",
            path.display()
        )
    } else {
        anyhow::anyhow!("{}: {e}", path.display())
    }
}
