//! Library surface of the SignedPulse client: the handshake/pulse logic plus the
//! CLI entry point (`cli::run_cli`), exposed so the `signedpulse` umbrella crate
//! can provide the binary.

pub mod cli;
pub mod client;
