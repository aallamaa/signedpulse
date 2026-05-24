//! Wire protocol: a compact, hand-rolled binary framing plus the canonical
//! signing payloads both peers build identically.
//!
//! Each cleartext packet is `header(2) || body`, where the 16-bit header packs
//! a magic byte, a 4-bit version and a 4-bit packet type. All integers are
//! little-endian. `client_id` is a 256-bit value. Signatures are never computed
//! over the wire bytes — they cover the stable text payloads produced by
//! [`hello_signing_payload`] / [`response_signing_payload`], so the exact byte
//! layout here is not security-relevant.
//!
//! When full-packet encryption is enabled the datagram on the wire is instead a
//! bare sealed blob (see `crypto::seal`/`open`) whose *plaintext* is one of
//! these binary packets; framing/decoding below always operates on that
//! cleartext form.

use thiserror::Error;

/// Protocol identifier, used only as a label inside the signing payloads.
pub const PROTOCOL_NAME: &str = "signedpulse";

/// Protocol version (4-bit on the wire).
pub const PROTOCOL_VERSION: u8 = 1;

/// First header byte: a fixed marker (cleartext mode only).
const MAGIC: u8 = 0x5A;

const TYPE_HELLO: u8 = 0;
const TYPE_CHALLENGE: u8 = 1;
const TYPE_RESPONSE: u8 = 2;

/// Field sizes (bytes).
pub const CLIENT_ID_LEN: usize = 32;
const HELLO_NONCE_LEN: usize = 16;
const CHALLENGE_NONCE_LEN: usize = 32;
const SIG_LEN: usize = 64;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("packet too short")]
    Truncated,
    #[error("bad magic byte")]
    BadMagic,
    #[error("unsupported protocol version {0}")]
    WrongVersion(u8),
    #[error("unknown packet type {0}")]
    UnknownType(u8),
    #[error("trailing bytes after packet")]
    TrailingBytes,
    #[error("invalid client_id hex")]
    BadClientIdHex,
}

/// A 256-bit client identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientId(pub [u8; CLIENT_ID_LEN]);

impl ClientId {
    /// Lowercase hex (64 chars), as stored in config.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(CLIENT_ID_LEN * 2);
        for b in self.0 {
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
        }
        s
    }

    /// Parse 64 hex chars into a `ClientId`.
    pub fn from_hex(s: &str) -> Result<Self, ProtocolError> {
        let s = s.trim();
        if s.len() != CLIENT_ID_LEN * 2 {
            return Err(ProtocolError::BadClientIdHex);
        }
        let mut out = [0u8; CLIENT_ID_LEN];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|_| ProtocolError::BadClientIdHex)?;
        }
        Ok(ClientId(out))
    }
}

impl std::fmt::Debug for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Short prefix keeps logs readable.
        write!(f, "ClientId({}…)", &self.to_hex()[..12])
    }
}

impl std::fmt::Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// HELLO — client announces itself and prompts a challenge. Signed (the
/// signature covers the timestamp + a fresh per-HELLO nonce) so the server can
/// reply only to authorized clients and reject replays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub client_id: ClientId,
    pub client_timestamp_unix: i64,
    pub hello_nonce: [u8; HELLO_NONCE_LEN],
    pub signature: [u8; SIG_LEN],
}

/// CHALLENGE — server's reply carrying the single-use nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub client_id: ClientId,
    pub nonce: [u8; CHALLENGE_NONCE_LEN],
    pub expires_at_unix: i64,
}

/// RESPONSE — the client's signature over the canonical payload, plus an
/// optional sealed parameter blob (ciphertext; the signature covers it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub client_id: ClientId,
    pub nonce: [u8; CHALLENGE_NONCE_LEN],
    /// Raw X25519 sealed-box bytes (see `crypto::seal_param`); `None` if absent.
    pub param: Option<Vec<u8>>,
    pub signature: [u8; SIG_LEN],
}

/// One of the three packet bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Hello(Hello),
    Challenge(Challenge),
    Response(Response),
}

fn header(packet_type: u8) -> [u8; 2] {
    [MAGIC, (PROTOCOL_VERSION << 4) | (packet_type & 0x0f)]
}

impl Packet {
    /// Encode this packet to its cleartext binary form.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Packet::Hello(h) => {
                out.extend_from_slice(&header(TYPE_HELLO));
                out.extend_from_slice(&h.client_id.0);
                out.extend_from_slice(&h.client_timestamp_unix.to_le_bytes());
                out.extend_from_slice(&h.hello_nonce);
                out.extend_from_slice(&h.signature);
            }
            Packet::Challenge(c) => {
                out.extend_from_slice(&header(TYPE_CHALLENGE));
                out.extend_from_slice(&c.client_id.0);
                out.extend_from_slice(&c.nonce);
                out.extend_from_slice(&c.expires_at_unix.to_le_bytes());
            }
            Packet::Response(r) => {
                out.extend_from_slice(&header(TYPE_RESPONSE));
                out.extend_from_slice(&r.client_id.0);
                out.extend_from_slice(&r.nonce);
                let param = r.param.as_deref().unwrap_or(&[]);
                out.extend_from_slice(&(param.len() as u16).to_le_bytes());
                out.extend_from_slice(param);
                out.extend_from_slice(&r.signature);
            }
        }
        out
    }

    /// Decode a cleartext binary packet, validating magic, version, type and
    /// exact length.
    pub fn decode(bytes: &[u8]) -> Result<Packet, ProtocolError> {
        let mut r = Reader::new(bytes);
        let magic = r.u8()?;
        if magic != MAGIC {
            return Err(ProtocolError::BadMagic);
        }
        let vt = r.u8()?;
        let version = vt >> 4;
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::WrongVersion(version));
        }
        let packet = match vt & 0x0f {
            TYPE_HELLO => Packet::Hello(Hello {
                client_id: ClientId(r.array::<CLIENT_ID_LEN>()?),
                client_timestamp_unix: r.i64()?,
                hello_nonce: r.array::<HELLO_NONCE_LEN>()?,
                signature: r.array::<SIG_LEN>()?,
            }),
            TYPE_CHALLENGE => Packet::Challenge(Challenge {
                client_id: ClientId(r.array::<CLIENT_ID_LEN>()?),
                nonce: r.array::<CHALLENGE_NONCE_LEN>()?,
                expires_at_unix: r.i64()?,
            }),
            TYPE_RESPONSE => {
                let client_id = ClientId(r.array::<CLIENT_ID_LEN>()?);
                let nonce = r.array::<CHALLENGE_NONCE_LEN>()?;
                let param_len = r.u16()? as usize;
                let param_bytes = r.take(param_len)?.to_vec();
                let signature = r.array::<SIG_LEN>()?;
                Packet::Response(Response {
                    client_id,
                    nonce,
                    param: if param_len == 0 {
                        None
                    } else {
                        Some(param_bytes)
                    },
                    signature,
                })
            }
            other => return Err(ProtocolError::UnknownType(other)),
        };
        if !r.is_empty() {
            return Err(ProtocolError::TrailingBytes);
        }
        Ok(packet)
    }
}

/// Minimal bounds-checked byte reader.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self.pos.checked_add(n).ok_or(ProtocolError::Truncated)?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(ProtocolError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ProtocolError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn i64(&mut self) -> Result<i64, ProtocolError> {
        let b = self.take(8)?;
        Ok(i64::from_le_bytes(b.try_into().unwrap()))
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
}

/// Canonical, deterministic message the client signs in a RESPONSE and the
/// server re-creates to verify. Plain UTF-8, fixed field order; both peers MUST
/// call this exact function. `client_id` is hex; `nonce`/`param` are base64. The
/// `param` line is the base64 *ciphertext* (or empty) — encrypt-then-sign.
///
/// ```text
/// signedpulse:v1:response
/// server_id=<server_id>
/// client_id=<client_id_hex>
/// nonce=<base64_nonce>
/// expires_at=<expires_at_unix>
/// param=<base64_ciphertext_or_empty>
/// ```
pub fn response_signing_payload(
    server_id: &str,
    client_id_hex: &str,
    nonce_b64: &str,
    expires_at_unix: i64,
    param_ciphertext_b64: &str,
) -> Vec<u8> {
    format!(
        "{PROTOCOL_NAME}:v{PROTOCOL_VERSION}:response\n\
         server_id={server_id}\n\
         client_id={client_id_hex}\n\
         nonce={nonce_b64}\n\
         expires_at={expires_at_unix}\n\
         param={param_ciphertext_b64}"
    )
    .into_bytes()
}

/// Canonical message the client signs in a HELLO. `server_id` is included so a
/// HELLO captured at one server cannot be replayed against a different one.
///
/// ```text
/// signedpulse:v1:hello
/// server_id=<server_id>
/// client_id=<client_id_hex>
/// timestamp=<client_timestamp_unix>
/// hello_nonce=<base64_nonce>
/// ```
pub fn hello_signing_payload(
    server_id: &str,
    client_id_hex: &str,
    timestamp_unix: i64,
    hello_nonce_b64: &str,
) -> Vec<u8> {
    format!(
        "{PROTOCOL_NAME}:v{PROTOCOL_VERSION}:hello\n\
         server_id={server_id}\n\
         client_id={client_id_hex}\n\
         timestamp={timestamp_unix}\n\
         hello_nonce={hello_nonce_b64}"
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(byte: u8) -> ClientId {
        ClientId([byte; CLIENT_ID_LEN])
    }

    #[test]
    fn client_id_hex_round_trips() {
        let id = cid(0xAB);
        assert_eq!(id.to_hex().len(), 64);
        assert_eq!(ClientId::from_hex(&id.to_hex()).unwrap(), id);
        assert!(ClientId::from_hex("xyz").is_err());
        assert!(ClientId::from_hex(&"a".repeat(63)).is_err());
    }

    #[test]
    fn packets_round_trip() {
        for packet in [
            Packet::Hello(Hello {
                client_id: cid(1),
                client_timestamp_unix: 1_700_000_000,
                hello_nonce: [7; HELLO_NONCE_LEN],
                signature: [9; SIG_LEN],
            }),
            Packet::Challenge(Challenge {
                client_id: cid(2),
                nonce: [3; CHALLENGE_NONCE_LEN],
                expires_at_unix: 1_700_000_030,
            }),
            Packet::Response(Response {
                client_id: cid(4),
                nonce: [5; CHALLENGE_NONCE_LEN],
                param: Some(vec![1, 2, 3, 4]),
                signature: [6; SIG_LEN],
            }),
            Packet::Response(Response {
                client_id: cid(4),
                nonce: [5; CHALLENGE_NONCE_LEN],
                param: None,
                signature: [6; SIG_LEN],
            }),
        ] {
            let bytes = packet.encode();
            assert_eq!(Packet::decode(&bytes).unwrap(), packet);
        }
    }

    #[test]
    fn hello_is_122_bytes() {
        let bytes = Packet::Hello(Hello {
            client_id: cid(1),
            client_timestamp_unix: 0,
            hello_nonce: [0; HELLO_NONCE_LEN],
            signature: [0; SIG_LEN],
        })
        .encode();
        assert_eq!(bytes.len(), 2 + 32 + 8 + 16 + 64);
    }

    #[test]
    fn decode_rejects_bad_magic_version_type_and_truncation() {
        let mut bytes = Packet::Challenge(Challenge {
            client_id: cid(2),
            nonce: [0; CHALLENGE_NONCE_LEN],
            expires_at_unix: 0,
        })
        .encode();

        let mut bad_magic = bytes.clone();
        bad_magic[0] = 0x00;
        assert!(matches!(
            Packet::decode(&bad_magic),
            Err(ProtocolError::BadMagic)
        ));

        let mut bad_ver = bytes.clone();
        bad_ver[1] = (9 << 4) | TYPE_CHALLENGE;
        assert!(matches!(
            Packet::decode(&bad_ver),
            Err(ProtocolError::WrongVersion(9))
        ));

        let mut bad_type = bytes.clone();
        bad_type[1] = (PROTOCOL_VERSION << 4) | 7;
        assert!(matches!(
            Packet::decode(&bad_type),
            Err(ProtocolError::UnknownType(7))
        ));

        bytes.truncate(10);
        assert!(matches!(
            Packet::decode(&bytes),
            Err(ProtocolError::Truncated)
        ));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = Packet::Challenge(Challenge {
            client_id: cid(2),
            nonce: [0; CHALLENGE_NONCE_LEN],
            expires_at_unix: 0,
        })
        .encode();
        bytes.push(0xFF);
        assert!(matches!(
            Packet::decode(&bytes),
            Err(ProtocolError::TrailingBytes)
        ));
    }

    #[test]
    fn response_canonical_payload_is_stable_and_exact() {
        let payload = response_signing_payload(
            "signedpulse-main",
            "ab",
            "QUJDREVG",
            1_700_000_030,
            "Q0lQSEVS",
        );
        let expected = "signedpulse:v1:response\n\
             server_id=signedpulse-main\n\
             client_id=ab\n\
             nonce=QUJDREVG\n\
             expires_at=1700000030\n\
             param=Q0lQSEVS";
        assert_eq!(payload, expected.as_bytes());
    }

    #[test]
    fn canonical_payloads_change_with_each_field() {
        let base = response_signing_payload("s", "c", "n", 1, "p");
        assert_ne!(base, response_signing_payload("S", "c", "n", 1, "p"));
        assert_ne!(base, response_signing_payload("s", "C", "n", 1, "p"));
        assert_ne!(base, response_signing_payload("s", "c", "N", 1, "p"));
        assert_ne!(base, response_signing_payload("s", "c", "n", 2, "p"));
        assert_ne!(base, response_signing_payload("s", "c", "n", 1, "P"));

        let hbase = hello_signing_payload("s", "c", 1, "n");
        assert_ne!(hbase, hello_signing_payload("S", "c", 1, "n"));
        assert_ne!(hbase, hello_signing_payload("s", "C", 1, "n"));
        assert_ne!(hbase, hello_signing_payload("s", "c", 2, "n"));
        assert_ne!(hbase, hello_signing_payload("s", "c", 1, "N"));
    }
}
