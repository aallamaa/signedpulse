//! A small, time-bounded "have I seen this before?" cache.
//!
//! Used to de-replay HELLO packets: the server records each accepted
//! `(client_id, hello_nonce)` for a short window. A byte-for-byte replay of a
//! HELLO collides with its earlier entry and is rejected, while genuinely fresh
//! HELLOs (each carrying a new random nonce) pass. Entries expire so memory is
//! bounded by the accepted HELLO rate over the window.

use std::collections::HashMap;
use std::sync::Mutex;

pub struct SeenCache {
    // Maps an opaque key to the unix time at which the entry may be forgotten.
    entries: Mutex<HashMap<Vec<u8>, i64>>,
}

impl SeenCache {
    pub fn new() -> Self {
        SeenCache {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Record `key` if it is not already present (or its previous entry has
    /// expired). Returns `true` when the key is newly accepted, `false` when it
    /// was already seen within its window (i.e. a replay).
    pub fn insert_if_absent(&self, key: Vec<u8>, now: i64, ttl_seconds: u64) -> bool {
        let mut entries = self.entries.lock().unwrap();
        match entries.get(&key) {
            // A live, unexpired entry means this is a replay.
            Some(&expires_at) if now <= expires_at => false,
            // Absent or expired: (re)accept and refresh the expiry.
            _ => {
                let expires = (now as i128 + ttl_seconds as i128).min(i64::MAX as i128) as i64;
                entries.insert(key, expires);
                true
            }
        }
    }

    /// Drop entries whose window has passed. Returns the number removed.
    pub fn purge_expired(&self, now: i64) -> usize {
        let mut entries = self.entries.lock().unwrap();
        let before = entries.len();
        entries.retain(|_, &mut expires_at| now <= expires_at);
        before - entries.len()
    }

    #[cfg(test)]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

impl Default for SeenCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_insert_accepted_duplicate_rejected() {
        let cache = SeenCache::new();
        let now = 1_000;
        assert!(cache.insert_if_absent(b"key".to_vec(), now, 60));
        assert!(
            !cache.insert_if_absent(b"key".to_vec(), now, 60),
            "second insert of same key within window is a replay"
        );
    }

    #[test]
    fn distinct_keys_both_accepted() {
        let cache = SeenCache::new();
        let now = 1_000;
        assert!(cache.insert_if_absent(b"a".to_vec(), now, 60));
        assert!(cache.insert_if_absent(b"b".to_vec(), now, 60));
    }

    #[test]
    fn key_reaccepted_after_expiry() {
        let cache = SeenCache::new();
        assert!(cache.insert_if_absent(b"key".to_vec(), 1_000, 60));
        // Past the TTL the key is forgotten and may be accepted again.
        assert!(cache.insert_if_absent(b"key".to_vec(), 1_061, 60));
    }

    #[test]
    fn purge_removes_only_expired() {
        let cache = SeenCache::new();
        cache.insert_if_absent(b"old".to_vec(), 1_000, 30);
        cache.insert_if_absent(b"new".to_vec(), 1_000, 120);
        // At t=1040, "old" (expires 1030) is gone, "new" (expires 1120) remains.
        assert_eq!(cache.purge_expired(1_040), 1);
        assert_eq!(cache.len(), 1);
    }
}
