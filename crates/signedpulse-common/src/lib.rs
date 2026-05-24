//! Shared building blocks for the SignedPulse client and server.
//!
//! This crate intentionally contains *no* network or async code. It holds the
//! wire protocol types, the canonical signing payload, the cryptographic
//! helpers built on Ed25519, and the TOML configuration structures. Keeping
//! these in one dependency-light crate means the client and server can never
//! disagree about how a packet is encoded or how a signature is computed.

pub mod config;
pub mod crypto;
pub mod protocol;
pub mod service;
pub mod status;

pub use protocol::{Challenge, ClientId, Hello, Packet, Response, PROTOCOL_NAME, PROTOCOL_VERSION};
