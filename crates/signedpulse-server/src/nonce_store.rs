//! In-memory store of issued challenge nonces.
//!
//! Each nonce is bound to the client and the exact UDP source endpoint that
//! requested it, plus a creation/expiry time, and is single-use. The store is
//! deliberately behind a small, synchronous API so that a persistent or
//! distributed backend could replace it later without touching the server loop.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// The binding recorded for an issued nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceEntry {
    pub client_id: String,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    used: bool,
}

/// Why a nonce consumption attempt was rejected. Used for safe, specific logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumeError {
    Unknown,
    AlreadyUsed,
    Expired,
    ClientMismatch,
    EndpointMismatch,
}

impl ConsumeError {
    pub fn reason(&self) -> &'static str {
        match self {
            ConsumeError::Unknown => "nonce unknown",
            ConsumeError::AlreadyUsed => "nonce already used (replay)",
            ConsumeError::Expired => "nonce expired",
            ConsumeError::ClientMismatch => "nonce client_id mismatch",
            ConsumeError::EndpointMismatch => "nonce source endpoint mismatch",
        }
    }
}

/// Current unix time in seconds.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub struct NonceStore {
    // Keyed by the raw nonce bytes.
    entries: Mutex<HashMap<Vec<u8>, NonceEntry>>,
}

impl NonceStore {
    pub fn new() -> Self {
        NonceStore {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Record a freshly issued nonce together with its binding. `expires_at_unix`
    /// is supplied by the caller so it is identical to the value placed in the
    /// CHALLENGE and signed by the client (a single source of truth — never
    /// recomputed from a second clock read).
    pub fn insert(
        &self,
        nonce: Vec<u8>,
        client_id: String,
        source_ip: IpAddr,
        source_port: u16,
        expires_at_unix: i64,
    ) {
        let entry = NonceEntry {
            client_id,
            source_ip,
            source_port,
            created_at_unix: now_unix(),
            expires_at_unix,
            used: false,
        };
        self.entries.lock().unwrap().insert(nonce, entry);
    }

    /// Check all bindings without mutating. Order is chosen so the most
    /// security-relevant mismatches (replay, expiry) are detected first.
    fn check(
        entry: &NonceEntry,
        client_id: &str,
        source_ip: IpAddr,
        source_port: u16,
        now: i64,
    ) -> Result<(), ConsumeError> {
        if entry.used {
            return Err(ConsumeError::AlreadyUsed);
        }
        if now > entry.expires_at_unix {
            return Err(ConsumeError::Expired);
        }
        if entry.client_id != client_id {
            return Err(ConsumeError::ClientMismatch);
        }
        if entry.source_ip != source_ip || entry.source_port != source_port {
            return Err(ConsumeError::EndpointMismatch);
        }
        Ok(())
    }

    /// Peek: verify all bindings and return the entry **without** marking it
    /// used. Lets the caller verify the signature first, so a bad-signature
    /// RESPONSE does not burn the nonce.
    pub fn validate(
        &self,
        nonce: &[u8],
        client_id: &str,
        source_ip: IpAddr,
        source_port: u16,
        now: i64,
    ) -> Result<NonceEntry, ConsumeError> {
        let entries = self.entries.lock().unwrap();
        let entry = entries.get(nonce).ok_or(ConsumeError::Unknown)?;
        Self::check(entry, client_id, source_ip, source_port, now)?;
        Ok(entry.clone())
    }

    /// Atomically verify all bindings and consume the nonce — the single-use
    /// gate. On success the nonce is permanently marked used so a replay (even a
    /// concurrent one that also passed `validate`) cannot succeed.
    pub fn consume(
        &self,
        nonce: &[u8],
        client_id: &str,
        source_ip: IpAddr,
        source_port: u16,
        now: i64,
    ) -> Result<NonceEntry, ConsumeError> {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.get_mut(nonce).ok_or(ConsumeError::Unknown)?;
        Self::check(entry, client_id, source_ip, source_port, now)?;
        entry.used = true;
        Ok(entry.clone())
    }

    /// Drop entries that have expired. Used nonces are kept until expiry so that
    /// a replay within the TTL window is still recognized as a replay rather
    /// than an unknown nonce. Returns the number removed.
    pub fn purge_expired(&self, now: i64) -> usize {
        let mut entries = self.entries.lock().unwrap();
        let before = entries.len();
        entries.retain(|_, e| now <= e.expires_at_unix);
        before - entries.len()
    }

    #[cfg(test)]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

impl Default for NonceStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5))
    }

    fn seed(store: &NonceStore, nonce: &[u8]) {
        store.insert(
            nonce.to_vec(),
            "client-001".into(),
            ip(),
            1111,
            now_unix() + 30,
        );
    }

    #[test]
    fn consume_succeeds_once_then_rejects_replay() {
        let store = NonceStore::new();
        seed(&store, b"nonce-a");
        let now = now_unix();
        assert!(store
            .consume(b"nonce-a", "client-001", ip(), 1111, now)
            .is_ok());
        // Second attempt with the identical packet must be flagged as replay.
        assert_eq!(
            store.consume(b"nonce-a", "client-001", ip(), 1111, now),
            Err(ConsumeError::AlreadyUsed)
        );
    }

    #[test]
    fn consume_rejects_unknown_nonce() {
        let store = NonceStore::new();
        assert_eq!(
            store.consume(b"missing", "client-001", ip(), 1111, now_unix()),
            Err(ConsumeError::Unknown)
        );
    }

    #[test]
    fn consume_rejects_expired_nonce() {
        let store = NonceStore::new();
        store.insert(
            b"n".to_vec(),
            "client-001".into(),
            ip(),
            1111,
            now_unix() + 30,
        );
        // Pretend "now" is well past the 30s TTL.
        let future = now_unix() + 31;
        assert_eq!(
            store.consume(b"n", "client-001", ip(), 1111, future),
            Err(ConsumeError::Expired)
        );
    }

    #[test]
    fn consume_rejects_wrong_client_id() {
        let store = NonceStore::new();
        seed(&store, b"n");
        assert_eq!(
            store.consume(b"n", "client-999", ip(), 1111, now_unix()),
            Err(ConsumeError::ClientMismatch)
        );
    }

    #[test]
    fn consume_rejects_wrong_endpoint() {
        let store = NonceStore::new();
        seed(&store, b"n");
        let other = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
        assert_eq!(
            store.consume(b"n", "client-001", other, 1111, now_unix()),
            Err(ConsumeError::EndpointMismatch)
        );
        assert_eq!(
            store.consume(b"n", "client-001", ip(), 2222, now_unix()),
            Err(ConsumeError::EndpointMismatch)
        );
    }

    #[test]
    fn purge_removes_only_expired() {
        let store = NonceStore::new();
        store.insert(b"keep".to_vec(), "c".into(), ip(), 1, now_unix() + 30);
        store.insert(b"gone".to_vec(), "c".into(), ip(), 1, now_unix() + 30);
        let now = now_unix();
        // Nothing expired yet.
        assert_eq!(store.purge_expired(now), 0);
        // Far future: both expired.
        assert_eq!(store.purge_expired(now + 31), 2);
        assert_eq!(store.len(), 0);
    }
}
