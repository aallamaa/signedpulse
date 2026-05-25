#!/usr/bin/env bash
#
# Publish the SignedPulse crates to crates.io, in dependency order.
#
#   common  ->  server, client  ->  signedpulse (umbrella)
#
# Usage:
#   scripts/publish.sh            # real publish (asks for confirmation)
#   scripts/publish.sh --dry-run  # gate + package the leaf crate, publish nothing
#
# Prerequisites:
#   * `cargo login <token>` has been run (token in ~/.cargo/credentials.toml),
#   * the working tree is committed, and ideally tagged `vX.Y.Z`,
#   * the version in Cargo.toml is the one you intend to release.
#
# Notes:
#   * Recent cargo (>=1.66) waits for each crate to appear in the index before
#     returning, so the next crate's dependency resolves — no manual sleeps.
#   * Published versions are immutable; you cannot overwrite, only yank + bump.
#   * Re-running after a partial publish skips versions already on crates.io.
set -euo pipefail

# Dependency order: a crate must be published before anything that depends on it.
CRATES=(signedpulse-common signedpulse-server signedpulse-client signedpulse)

cd "$(dirname "$0")/.."

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

VERSION=$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')
echo "SignedPulse publish — version v${VERSION}"
echo "crates (in order): ${CRATES[*]}"
echo

# --- Pre-flight: clean tree + the full quality gate -------------------------
if [ -n "$(git status --porcelain)" ]; then
  echo "ERROR: working tree has uncommitted changes — commit (and tag v${VERSION}) first." >&2
  exit 1
fi
if [ ! -f "${CARGO_HOME:-$HOME/.cargo}/credentials.toml" ] && [ ! -f "${CARGO_HOME:-$HOME/.cargo}/credentials" ]; then
  echo "WARNING: no crates.io credentials found — run \`cargo login <token>\` first." >&2
fi

echo "==> pre-flight: fmt / clippy / test"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
echo "    gate passed."
echo

# --- Dry run: only the leaf crate can verify before its deps are live -------
if [ "$DRY_RUN" = 1 ]; then
  echo "==> dry-run: packaging ${CRATES[0]} (dependent crates can't be verified"
  echo "    until ${CRATES[0]} is actually on crates.io)"
  cargo publish -p "${CRATES[0]}" --dry-run
  echo "    dry-run OK."
  exit 0
fi

# --- Confirm ----------------------------------------------------------------
echo "About to publish v${VERSION} to crates.io. This is PERMANENT (immutable)."
read -r -p "Proceed? [y/N] " ans
case "$ans" in
  y | Y) ;;
  *) echo "aborted."; exit 1 ;;
esac

# --- Publish in order, tolerating an already-published version on re-run -----
for crate in "${CRATES[@]}"; do
  echo
  echo "==> cargo publish -p ${crate}"
  if out=$(cargo publish -p "$crate" 2>&1); then
    echo "$out" | tail -3
    echo "    published ${crate}@${VERSION}"
  else
    echo "$out" | tail -8
    if echo "$out" | grep -qiE "already (uploaded|exists)|is already being published|already uploaded"; then
      echo "    ${crate}@${VERSION} already on crates.io — skipping."
    else
      echo "ERROR: publishing ${crate} failed (see above)." >&2
      exit 1
    fi
  fi
done

echo
echo "All crates published at v${VERSION}."
echo "Upgrade an install with:  cargo install --force signedpulse"
echo "If you haven't tagged the release:  git tag -a v${VERSION} -m 'v${VERSION}' && git push --tags"
