//! Per-source-IP rate limiting for HELLO packets, and per-key cooldown tracking
//! for command executions.
//!
//! HELLO handling is cheap but mints a nonce and sends a reply, so an unauthed
//! flood could be used for amplification or memory pressure. A simple
//! fixed-window counter per source IP bounds that. Cooldown tracking prevents a
//! verified client (or source IP) from triggering the hook too frequently.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Fixed-window rate limiter keyed by source IP.
pub struct HelloRateLimiter {
    max_per_window: u32,
    window: std::time::Duration,
    /// Hard cap on distinct tracked IPs (0 = unbounded). When full, a new IP is
    /// allowed through but not tracked, bounding memory under a spoofed flood.
    max_entries: usize,
    state: Mutex<HashMap<IpAddr, Window>>,
}

struct Window {
    window_start: Instant,
    count: u32,
}

impl HelloRateLimiter {
    pub fn new(max_per_window: u32, window_seconds: u64, max_entries: usize) -> Self {
        HelloRateLimiter {
            max_per_window,
            window: std::time::Duration::from_secs(window_seconds.max(1)),
            max_entries,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if the HELLO is allowed; false if the source IP is over its
    /// budget for the current window.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_at(ip, Instant::now())
    }

    fn check_at(&self, ip: IpAddr, now: Instant) -> bool {
        // A zero budget disables the limiter entirely.
        if self.max_per_window == 0 {
            return true;
        }
        let mut state = self.state.lock().unwrap();
        // Table full + new IP: allow but don't track (the in-flight semaphore and
        // IP blacklist remain the primary flood defenses).
        if self.max_entries > 0 && state.len() >= self.max_entries && !state.contains_key(&ip) {
            return true;
        }
        let entry = state.entry(ip).or_insert(Window {
            window_start: now,
            count: 0,
        });
        if now.duration_since(entry.window_start) >= self.window {
            entry.window_start = now;
            entry.count = 0;
        }
        if entry.count >= self.max_per_window {
            return false;
        }
        entry.count += 1;
        true
    }

    /// Drop windows that are fully in the past, to bound memory.
    pub fn purge_stale(&self) {
        let now = Instant::now();
        let window = self.window;
        self.state
            .lock()
            .unwrap()
            .retain(|_, w| now.duration_since(w.window_start) < window);
    }
}

/// Tracks the last successful command execution per arbitrary key (client_id or
/// source IP string) to enforce a cooldown.
pub struct CooldownTracker {
    cooldown: std::time::Duration,
    last: Mutex<HashMap<String, Instant>>,
}

impl CooldownTracker {
    pub fn new(cooldown_seconds: u64) -> Self {
        CooldownTracker {
            cooldown: std::time::Duration::from_secs(cooldown_seconds),
            last: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if `key` is still cooling down (i.e. should be skipped).
    pub fn in_cooldown(&self, key: &str) -> bool {
        if self.cooldown.is_zero() {
            return false;
        }
        let now = Instant::now();
        match self.last.lock().unwrap().get(key) {
            Some(&t) => now.duration_since(t) < self.cooldown,
            None => false,
        }
    }

    /// Record that `key` just executed successfully.
    pub fn mark(&self, key: &str) {
        if self.cooldown.is_zero() {
            return;
        }
        self.last
            .lock()
            .unwrap()
            .insert(key.to_string(), Instant::now());
    }

    /// Drop entries older than the cooldown so the map cannot grow unbounded.
    pub fn purge_stale(&self) {
        if self.cooldown.is_zero() {
            return;
        }
        let now = Instant::now();
        let cooldown = self.cooldown;
        self.last
            .lock()
            .unwrap()
            .retain(|_, &mut t| now.duration_since(t) < cooldown);
    }
}

/// Blacklists source IPs that send too many faulty packets, so an attacker
/// cannot saturate the CPU by flooding undecryptable/garbage datagrams: once an
/// IP is blacklisted, its packets are dropped *before* any decryption attempt.
pub struct Blacklist {
    /// Faulty packets tolerated before blacklisting. 0 disables the feature.
    threshold: u32,
    duration: Duration,
    /// If more than `attack_threshold` distinct IPs are blacklisted within
    /// `attack_window`, the server is "under attack" (see `under_attack`).
    attack_threshold: u32,
    /// If more than `rejection_threshold` packets are *rejected* (any reason —
    /// including post-decrypt auth failures that never blacklist an IP) within
    /// `attack_window`, also enter lockdown. This catches a flood of well-formed
    /// but unauthenticated sealed packets that burns CPU without blacklisting.
    /// 0 disables this trigger.
    rejection_threshold: u32,
    attack_window: Duration,
    /// Hard cap on distinct tracked IPs (0 = unbounded); bounds memory under a
    /// spoofed-source flood. When full, new IPs are simply not tracked.
    max_entries: usize,
    state: Mutex<HashMap<IpAddr, Entry>>,
    /// Timestamps of recent blacklisting events (one per IP newly blocked).
    events: Mutex<VecDeque<Instant>>,
    /// Timestamps of recent rejected packets (any reason).
    rejections: Mutex<VecDeque<Instant>>,
    /// Monotonic base for the lockdown hold-down timer.
    base: Instant,
    /// Lockdown is engaged until this many ms after `base` (0 = off). Re-armed
    /// on each trip/rejection AND while packets are still being shed at a high
    /// rate (see `note_lockdown_drop`), so a sustained flood keeps it latched (no
    /// flap) yet it auto-clears one `attack_window` after the flood stops — a
    /// trickle of background scan noise can't hold it on. Lock-free hot-path read.
    lockdown_until_ms: AtomicU64,
    /// Fixed-window counter of packets shed at the lockdown gate, used to decide
    /// whether the drop *rate* still warrants re-arming. Only ever written by the
    /// single recv task, so plain atomics are race-free here.
    drop_window_start_ms: AtomicU64,
    drop_count: AtomicU64,
}

struct Entry {
    faults: u32,
    /// `Some(instant)` once blacklisted, until which the IP stays blocked.
    blocked_until: Option<Instant>,
}

impl Blacklist {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        threshold: u32,
        duration_seconds: u64,
        attack_threshold: u32,
        rejection_threshold: u32,
        attack_window_seconds: u64,
        max_entries: usize,
    ) -> Self {
        Blacklist {
            threshold,
            duration: Duration::from_secs(duration_seconds),
            attack_threshold,
            rejection_threshold,
            attack_window: Duration::from_secs(attack_window_seconds.max(1)),
            max_entries,
            state: Mutex::new(HashMap::new()),
            events: Mutex::new(VecDeque::new()),
            rejections: Mutex::new(VecDeque::new()),
            base: Instant::now(),
            lockdown_until_ms: AtomicU64::new(0),
            drop_window_start_ms: AtomicU64::new(0),
            drop_count: AtomicU64::new(0),
        }
    }

    /// True while lockdown is engaged — a lock-free atomic read for the hot path.
    pub fn under_attack(&self) -> bool {
        if self.attack_threshold == 0 && self.rejection_threshold == 0 {
            return false;
        }
        self.now_ms() < self.lockdown_until_ms.load(Ordering::Relaxed)
    }

    fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }

    /// Engage (or extend) lockdown for one `attack_window` from now. `fetch_max`
    /// avoids lost updates between concurrent callers.
    fn arm_lockdown(&self) {
        let until = self.now_ms() + self.attack_window.as_millis() as u64;
        self.lockdown_until_ms.fetch_max(until, Ordering::Relaxed);
    }

    /// Called by the recv loop for each packet dropped at the lockdown gate.
    /// Re-arms lockdown ONLY while the drop *rate* stays above the threshold, so
    /// a sustained flood keeps it latched but a trickle of background noise (a
    /// few stray packets per window) cannot hold it on after the flood ends.
    /// Single-writer (the recv task), so the plain-atomic fixed-window counter is
    /// race-free.
    pub fn note_lockdown_drop(&self) {
        let thresh = if self.rejection_threshold > 0 {
            self.rejection_threshold
        } else if self.attack_threshold > 0 {
            self.attack_threshold
        } else {
            return; // lockdown disabled
        } as u64;

        let now = self.now_ms();
        let window_ms = self.attack_window.as_millis() as u64;
        if now.saturating_sub(self.drop_window_start_ms.load(Ordering::Relaxed)) > window_ms {
            // New window.
            self.drop_window_start_ms.store(now, Ordering::Relaxed);
            self.drop_count.store(1, Ordering::Relaxed);
        } else {
            let count = self.drop_count.fetch_add(1, Ordering::Relaxed) + 1;
            if count > thresh {
                self.arm_lockdown();
            }
        }
    }

    fn trim(window: Duration, q: &mut VecDeque<Instant>, now: Instant) {
        while let Some(&front) = q.front() {
            if now.duration_since(front) > window {
                q.pop_front();
            } else {
                break;
            }
        }
    }

    /// Record a rejected packet (any reason) toward the lockdown rejection-rate
    /// trigger. Cheap: amortized O(1) push + front-trim.
    pub fn note_rejection(&self) {
        if self.rejection_threshold == 0 {
            return;
        }
        let now = Instant::now();
        let mut rejections = self.rejections.lock().unwrap();
        rejections.push_back(now);
        Self::trim(self.attack_window, &mut rejections, now);
        let over = rejections.len() as u32 > self.rejection_threshold;
        drop(rejections);
        if over {
            self.arm_lockdown();
        }
    }

    /// Cheap check used before any expensive work. True ⇒ drop immediately.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        if self.threshold == 0 {
            return false;
        }
        self.is_blocked_at(ip, Instant::now())
    }

    fn is_blocked_at(&self, ip: IpAddr, now: Instant) -> bool {
        match self.state.lock().unwrap().get(&ip) {
            Some(e) => e.blocked_until.map(|t| now < t).unwrap_or(false),
            None => false,
        }
    }

    /// Record a faulty packet from `ip`. Returns true **only** on the packet that
    /// newly blacklists the IP, so the caller logs exactly once per event; while
    /// the IP is already blocked it returns false (silent).
    pub fn record_faulty(&self, ip: IpAddr) -> bool {
        if self.threshold == 0 {
            return false;
        }
        self.record_faulty_at(ip, Instant::now())
    }

    fn record_faulty_at(&self, ip: IpAddr, now: Instant) -> bool {
        if self.threshold == 0 {
            return false;
        }
        // Compute the trip under the state lock, then release it before touching
        // the events lock (consistent ordering: never hold both at once here).
        let tripped = {
            let mut state = self.state.lock().unwrap();
            // Memory cap: under a spoofed-source flood, stop tracking new IPs
            // once the table is full (the in-flight semaphore bounds the CPU).
            if self.max_entries > 0 && state.len() >= self.max_entries && !state.contains_key(&ip) {
                false
            } else {
                let entry = state.entry(ip).or_insert(Entry {
                    faults: 0,
                    blocked_until: None,
                });
                if let Some(until) = entry.blocked_until {
                    if now < until {
                        // Already blacklisted: extend the block but stay silent, so
                        // the blacklisting is logged only the first time.
                        entry.blocked_until = Some(now + self.duration);
                        false
                    } else {
                        // A previous block expired; start counting fresh.
                        entry.faults = 1;
                        entry.blocked_until = None;
                        1 > self.threshold
                    }
                } else {
                    entry.faults += 1;
                    if entry.faults > self.threshold {
                        entry.blocked_until = Some(now + self.duration);
                        true
                    } else {
                        false
                    }
                }
            }
        };
        if tripped {
            let over = {
                let mut events = self.events.lock().unwrap();
                events.push_back(now);
                Self::trim(self.attack_window, &mut events, now);
                events.len() as u32 > self.attack_threshold
            };
            if over {
                self.arm_lockdown();
            }
        }
        tripped
    }

    /// Drop entries whose block has expired and that have no recent faults, and
    /// trim the rolling windows. (Lockdown auto-clears via its hold-down timer,
    /// so nothing to recompute here.)
    pub fn purge_stale(&self) {
        let now = Instant::now();
        self.state
            .lock()
            .unwrap()
            .retain(|_, e| e.blocked_until.map(|t| now < t).unwrap_or(false));
        Self::trim(self.attack_window, &mut self.events.lock().unwrap(), now);
        Self::trim(
            self.attack_window,
            &mut self.rejections.lock().unwrap(),
            now,
        );
    }
}

/// Tracks source IPs that recently completed a successful exchange ("active"),
/// so that during an attack the server can keep serving them while dropping
/// unknown sources before any decryption.
pub struct ActiveIps {
    ttl: Duration,
    max_entries: usize,
    seen: Mutex<HashMap<IpAddr, Instant>>,
}

impl ActiveIps {
    pub fn new(ttl_seconds: u64, max_entries: usize) -> Self {
        ActiveIps {
            ttl: Duration::from_secs(ttl_seconds.max(1)),
            max_entries: max_entries.max(1),
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Mark `ip` active now (e.g. on an authenticated HELLO or verified pulse).
    /// Only reachable after a signature check, so it cannot be driven by a pure
    /// source-spoofer; the `max_entries` cap is a hard bound on memory regardless.
    pub fn mark(&self, ip: IpAddr) {
        let mut seen = self.seen.lock().unwrap();
        // Refresh an existing entry freely; only the table-growing insert of a
        // genuinely new IP is gated by the cap (when full, refuse the new IP).
        if seen.contains_key(&ip) || seen.len() < self.max_entries {
            seen.insert(ip, Instant::now());
        }
    }

    pub fn is_active(&self, ip: IpAddr) -> bool {
        self.is_active_at(ip, Instant::now())
    }

    fn is_active_at(&self, ip: IpAddr, now: Instant) -> bool {
        match self.seen.lock().unwrap().get(&ip) {
            Some(&t) => now.duration_since(t) < self.ttl,
            None => false,
        }
    }

    pub fn purge_stale(&self) {
        let now = Instant::now();
        let ttl = self.ttl;
        self.seen
            .lock()
            .unwrap()
            .retain(|_, &mut t| now.duration_since(t) < ttl);
    }
}

/// One active access lease, keyed by `client_id`. Renewed on every verified
/// pulse; when it expires (no pulse for the TTL) the server may run the revoke
/// hook (see [`LeaseTracker`] for the IP reference-counting rule).
struct Lease {
    expires_at: Instant,
    ip: IpAddr,
    source_port: u16,
    param: Option<String>,
}

/// A lease that ended (expired or released) — the data the revoke hook needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpiredLease {
    pub ip: IpAddr,
    pub client_id: String,
    pub source_port: u16,
    pub param: Option<String>,
}

/// Per-**client** access leases for the port-knock "access while pulsing" model.
/// A verified pulse renews that client's lease (TTL derived from the client's
/// advertised interval); when the client stops pulsing its lease expires.
///
/// Identity (grant, `{new}`, cooldown, observability) follows the `client_id`,
/// but the *firewall* it controls filters on **source IP**, so the revoke hook
/// (which closes the IP pinhole) is **reference-counted by IP**: closing only
/// happens when the LAST client behind an IP leaves. `take_expired` / `release`
/// therefore report, per ended lease, whether its IP is now free of any other
/// live lease (`ip_freed`) — the caller runs the revoke only then. This keeps
/// co-NAT clients independent for grants while never tearing down a pinhole a
/// sibling client is still using.
pub struct LeaseTracker {
    max_entries: usize,
    leases: Mutex<HashMap<String, Lease>>,
}

impl LeaseTracker {
    pub fn new(max_entries: usize) -> Self {
        LeaseTracker {
            max_entries: max_entries.max(1),
            leases: Mutex::new(HashMap::new()),
        }
    }

    /// Create or renew `client_id`'s lease (its current source IP/port/param),
    /// with `ttl` from now. Returns `true` when this is a NEW or reactivated
    /// session for *this client* — no live lease for it immediately before (first
    /// pulse ever, or the first after its previous lease expired) — and `false`
    /// when it merely renews a live one. Only reachable post-signature, so
    /// unspoofable; a genuinely new client is gated by `max_entries` (refused
    /// when full, like `ActiveIps`).
    pub fn renew(
        &self,
        client_id: &str,
        ip: IpAddr,
        source_port: u16,
        param: Option<&str>,
        ttl: Duration,
    ) -> bool {
        self.renew_at(client_id, ip, source_port, param, ttl, Instant::now())
    }

    fn renew_at(
        &self,
        client_id: &str,
        ip: IpAddr,
        source_port: u16,
        param: Option<&str>,
        ttl: Duration,
        now: Instant,
    ) -> bool {
        let mut leases = self.leases.lock().unwrap();
        let is_new = match leases.get(client_id) {
            Some(l) => now >= l.expires_at,
            None => true,
        };
        let lease = Lease {
            expires_at: now + ttl,
            ip,
            source_port,
            param: param.map(|s| s.to_string()),
        };
        // Refresh an existing client freely; only a genuinely new client is gated
        // by the cap (refused tracking at saturation; grant still runs so access
        // works, it just won't be auto-revoked). `is_new` is still true so the
        // grant hook treats a refused client as a fresh session.
        if leases.contains_key(client_id) || leases.len() < self.max_entries {
            leases.insert(client_id.to_string(), lease);
        }
        is_new
    }

    /// Release `client_id`'s own lease for a client-initiated BYE (authenticated
    /// as that client, so no cross-client ownership concern). Returns the data
    /// the revoke hook needs plus `ip_freed` — `true` when no OTHER live lease
    /// references the same IP, i.e. the firewall pinhole should now close.
    pub fn release(&self, client_id: &str) -> Option<(ExpiredLease, bool)> {
        self.release_at(client_id, Instant::now())
    }

    fn release_at(&self, client_id: &str, now: Instant) -> Option<(ExpiredLease, bool)> {
        let mut leases = self.leases.lock().unwrap();
        let l = leases.remove(client_id)?;
        let ip_freed = !leases.values().any(|o| now < o.expires_at && o.ip == l.ip);
        Some((
            ExpiredLease {
                ip: l.ip,
                client_id: client_id.to_string(),
                source_port: l.source_port,
                param: l.param,
            },
            ip_freed,
        ))
    }

    /// Whether any client currently holds a non-expired lease for `ip`. Used by
    /// the revoke path to skip closing an IP that a (possibly different) client
    /// re-pulsed between the sweep and the hook running.
    pub fn is_ip_live(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        self.leases
            .lock()
            .unwrap()
            .values()
            .any(|l| now < l.expires_at && l.ip == ip)
    }

    /// Remove every expired lease and report, per ended lease, whether its IP is
    /// now free of any other live lease (`ip_freed`). When several expired leases
    /// share a freed IP, exactly one is marked `ip_freed = true` so the caller
    /// closes that pinhole once. Drains under a single lock.
    pub fn take_expired(&self) -> Vec<(ExpiredLease, bool)> {
        self.take_expired_at(Instant::now())
    }

    fn take_expired_at(&self, now: Instant) -> Vec<(ExpiredLease, bool)> {
        let mut leases = self.leases.lock().unwrap();
        let expired_keys: Vec<String> = leases
            .iter()
            .filter(|(_, l)| now >= l.expires_at)
            .map(|(k, _)| k.clone())
            .collect();
        // IPs still referenced by a (now necessarily live) remaining lease.
        let mut taken: Vec<(String, Lease)> = Vec::with_capacity(expired_keys.len());
        for k in expired_keys {
            if let Some(l) = leases.remove(&k) {
                taken.push((k, l));
            }
        }
        let live_ips: HashSet<IpAddr> = leases.values().map(|l| l.ip).collect();
        let mut freed_this_batch: HashSet<IpAddr> = HashSet::new();
        taken
            .into_iter()
            .map(|(cid, l)| {
                let ip_freed = !live_ips.contains(&l.ip) && freed_this_batch.insert(l.ip);
                (
                    ExpiredLease {
                        ip: l.ip,
                        client_id: cid,
                        source_port: l.source_port,
                        param: l.param,
                    },
                    ip_freed,
                )
            })
            .collect()
    }

    /// Count of live (non-expired) client leases, for status.
    pub fn active_count(&self) -> usize {
        let now = Instant::now();
        self.leases
            .lock()
            .unwrap()
            .values()
            .filter(|l| now < l.expires_at)
            .count()
    }

    /// Snapshot of each live lease for status: (source IP, client_id, seconds
    /// until it expires/revokes if no further pulse arrives).
    pub fn live_snapshot(&self) -> Vec<(IpAddr, String, u64)> {
        let now = Instant::now();
        self.leases
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, l)| now < l.expires_at)
            .map(|(cid, l)| (l.ip, cid.clone(), (l.expires_at - now).as_secs()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))
    }

    #[test]
    fn lease_renews_reactivates_and_expires() {
        let lt = LeaseTracker::new(1024);
        let t0 = Instant::now();
        let ttl = Duration::from_secs(10);
        // First pulse is a new session.
        assert!(lt.renew_at("cid", ip(1), 5, None, ttl, t0));
        assert_eq!(lt.take_expired_at(t0).len(), 0);
        // Renewal within TTL is not "new" and pushes expiry out.
        assert!(!lt.renew_at("cid", ip(1), 5, None, ttl, t0 + Duration::from_secs(5)));
        assert_eq!(
            lt.take_expired_at(t0 + Duration::from_secs(11)).len(),
            0,
            "renewal should have pushed expiry past t0+11"
        );
        // After it finally expires, take_expired drains it once; its IP is freed.
        let expired = lt.take_expired_at(t0 + Duration::from_secs(100));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0.ip, ip(1));
        assert!(expired[0].1, "sole lease on the IP → ip_freed");
        // A pulse after expiry is a new/reactivated session again.
        assert!(lt.renew_at("cid", ip(1), 5, None, ttl, t0 + Duration::from_secs(101)));
    }

    #[test]
    fn lease_is_ip_live_tracks_expiry() {
        let lt = LeaseTracker::new(1024);
        let t0 = Instant::now();
        let ttl = Duration::from_secs(10);
        assert!(!lt.is_ip_live(ip(1)), "no lease yet");
        lt.renew_at("c", ip(1), 1, None, ttl, t0);
        assert!(lt.is_ip_live(ip(1)), "within ttl");
    }

    #[test]
    fn lease_is_per_client_and_caps() {
        let lt = LeaseTracker::new(2);
        let t0 = Instant::now();
        let ttl = Duration::from_secs(10);
        // alice and bob each get their own lease (distinct client ids).
        assert!(lt.renew_at("alice", ip(1), 1, Some("a"), ttl, t0));
        assert!(lt.renew_at("bob", ip(2), 2, Some("b"), ttl, t0));
        // Table full (2 clients); a third distinct client is refused tracking.
        lt.renew_at("carol", ip(3), 3, None, ttl, t0);
        assert_eq!(lt.active_count(), 2);
        let mut expired = lt.take_expired_at(t0 + Duration::from_secs(11));
        expired.sort_by_key(|(e, _)| e.client_id.clone());
        assert_eq!(expired.len(), 2);
        let (alice, alice_freed) = &expired[0];
        assert_eq!(alice.client_id, "alice");
        assert_eq!(alice.source_port, 1);
        assert_eq!(alice.param.as_deref(), Some("a"));
        assert!(alice_freed, "alice was the only lease on ip(1)");
    }

    #[test]
    fn co_nat_clients_keep_pinhole_until_last_leaves() {
        let lt = LeaseTracker::new(1024);
        let t0 = Instant::now();
        let ttl = Duration::from_secs(10);
        // alice and bob share one source IP (behind the same NAT).
        lt.renew_at("alice", ip(1), 1, None, ttl, t0);
        lt.renew_at("bob", ip(1), 2, None, Duration::from_secs(30), t0);

        // alice's BYE releases only her lease; bob still holds the IP, so the
        // pinhole must NOT close.
        let (e, ip_freed) = lt.release_at("alice", t0 + Duration::from_secs(1)).unwrap();
        assert_eq!(e.client_id, "alice");
        assert!(!ip_freed, "bob still holds ip(1); must not close");
        assert!(lt.is_ip_live(ip(1)));

        // Now bob expires (alice already gone) → his expiry frees the IP.
        let expired = lt.take_expired_at(t0 + Duration::from_secs(31));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0.client_id, "bob");
        assert!(expired[0].1, "last client on the IP → ip_freed");
        assert!(!lt.is_ip_live(ip(1)));
    }

    #[test]
    fn batch_expiry_frees_shared_ip_exactly_once() {
        let lt = LeaseTracker::new(1024);
        let t0 = Instant::now();
        let ttl = Duration::from_secs(10);
        // Two clients on one IP, one on another — all expire in the same sweep.
        lt.renew_at("a", ip(1), 1, None, ttl, t0);
        lt.renew_at("b", ip(1), 2, None, ttl, t0);
        lt.renew_at("c", ip(2), 3, None, ttl, t0);
        let expired = lt.take_expired_at(t0 + Duration::from_secs(11));
        assert_eq!(expired.len(), 3);
        // ip(1) is shared by a+b → freed exactly once across the batch.
        let freed_ip1 = expired
            .iter()
            .filter(|(e, freed)| e.ip == ip(1) && *freed)
            .count();
        assert_eq!(freed_ip1, 1, "shared IP closed once, not per client");
        // ip(2) had a single client → freed once.
        let freed_ip2 = expired
            .iter()
            .filter(|(e, freed)| e.ip == ip(2) && *freed)
            .count();
        assert_eq!(freed_ip2, 1);
    }

    #[test]
    fn allows_up_to_budget_then_blocks() {
        let rl = HelloRateLimiter::new(3, 60, 0);
        let now = Instant::now();
        assert!(rl.check_at(ip(1), now));
        assert!(rl.check_at(ip(1), now));
        assert!(rl.check_at(ip(1), now));
        assert!(!rl.check_at(ip(1), now), "4th request must be blocked");
    }

    #[test]
    fn budget_resets_after_window() {
        let rl = HelloRateLimiter::new(1, 1, 0);
        let t0 = Instant::now();
        assert!(rl.check_at(ip(1), t0));
        assert!(!rl.check_at(ip(1), t0));
        let later = t0 + Duration::from_secs(2);
        assert!(rl.check_at(ip(1), later), "window should have reset");
    }

    #[test]
    fn separate_ips_have_separate_budgets() {
        let rl = HelloRateLimiter::new(1, 60, 0);
        let now = Instant::now();
        assert!(rl.check_at(ip(1), now));
        assert!(rl.check_at(ip(2), now));
    }

    #[test]
    fn zero_budget_disables_limiter() {
        let rl = HelloRateLimiter::new(0, 60, 0);
        let now = Instant::now();
        for _ in 0..1000 {
            assert!(rl.check_at(ip(1), now));
        }
    }

    #[test]
    fn cooldown_blocks_then_allows() {
        let cd = CooldownTracker::new(60);
        assert!(!cd.in_cooldown("client-001"));
        cd.mark("client-001");
        assert!(cd.in_cooldown("client-001"));
        assert!(!cd.in_cooldown("other"));
    }

    #[test]
    fn zero_cooldown_never_blocks() {
        let cd = CooldownTracker::new(0);
        cd.mark("c");
        assert!(!cd.in_cooldown("c"));
    }

    #[test]
    fn blacklist_blocks_after_threshold() {
        let bl = Blacklist::new(10, 300, 1000, 0, 10, 0);
        let now = Instant::now();
        // 10 faulty packets are tolerated; the 11th trips the blacklist.
        for _ in 0..10 {
            assert!(!bl.record_faulty_at(ip(1), now));
        }
        assert!(
            bl.record_faulty_at(ip(1), now),
            "11th fault should blacklist"
        );
        assert!(bl.is_blocked_at(ip(1), now));
        assert!(!bl.is_blocked_at(ip(2), now), "other IPs unaffected");
    }

    #[test]
    fn blacklist_logs_once_then_silent_while_blocked() {
        let bl = Blacklist::new(2, 300, 1000, 0, 10, 0);
        let now = Instant::now();
        assert!(!bl.record_faulty_at(ip(1), now)); // faults 1
        assert!(!bl.record_faulty_at(ip(1), now)); // faults 2 (== threshold, tolerated)
        assert!(
            bl.record_faulty_at(ip(1), now),
            "3rd trips the blacklist (logs once)"
        );
        // Already blocked: subsequent faults are silent.
        assert!(!bl.record_faulty_at(ip(1), now));
        assert!(!bl.record_faulty_at(ip(1), now));
        assert!(bl.is_blocked_at(ip(1), now));
    }

    #[test]
    fn blacklist_expires_after_duration() {
        let bl = Blacklist::new(1, 1, 1000, 0, 10, 0);
        let t0 = Instant::now();
        assert!(!bl.record_faulty_at(ip(1), t0));
        assert!(bl.record_faulty_at(ip(1), t0));
        assert!(bl.is_blocked_at(ip(1), t0));
        assert!(!bl.is_blocked_at(ip(1), t0 + Duration::from_secs(2)));
    }

    #[test]
    fn blacklist_threshold_zero_disables() {
        let bl = Blacklist::new(0, 300, 1000, 0, 10, 0);
        let now = Instant::now();
        for _ in 0..1000 {
            assert!(!bl.record_faulty_at(ip(1), now));
        }
        assert!(!bl.is_blocked_at(ip(1), now));
    }

    #[test]
    fn under_attack_trips_when_many_ips_blacklisted() {
        // Per-IP threshold 1 (trip on 2nd faulty packet); attack threshold 3 =>
        // the 4th distinct IP blacklisted in the window engages lockdown.
        let bl = Blacklist::new(1, 300, 3, 0, 10, 0);
        let now = Instant::now();
        for n in 1..=3u8 {
            assert!(!bl.record_faulty_at(ip(n), now));
            assert!(bl.record_faulty_at(ip(n), now));
        }
        assert!(!bl.under_attack(), "3 IPs is at threshold, not over");
        assert!(!bl.record_faulty_at(ip(4), now));
        assert!(bl.record_faulty_at(ip(4), now));
        assert!(bl.under_attack(), "4 IPs in window => lockdown engaged");
    }

    #[test]
    fn lockdown_drop_burst_keeps_lockdown_latched() {
        // Engage lockdown, then a burst of gate-drops above the threshold re-arms
        // it (keeps it latched while a flood is still being shed).
        let bl = Blacklist::new(0, 300, 0, 2, 10, 0);
        bl.note_rejection();
        bl.note_rejection();
        bl.note_rejection(); // > threshold(2) -> engaged
        assert!(bl.under_attack());
        for _ in 0..5 {
            bl.note_lockdown_drop(); // burst > threshold re-arms
        }
        assert!(bl.under_attack());
    }

    #[test]
    fn under_attack_trips_on_rejection_rate() {
        // No per-IP blacklisting (threshold 0 disables it), no distinct-IP
        // trigger; lockdown driven purely by rejection rate (>3 in the window).
        let bl = Blacklist::new(0, 300, 0, 3, 10, 0);
        for _ in 0..3 {
            bl.note_rejection();
        }
        assert!(!bl.under_attack(), "3 rejections is at threshold, not over");
        bl.note_rejection();
        assert!(bl.under_attack(), "4th rejection trips lockdown");
    }

    #[test]
    fn active_ips_tracks_recent_then_expires() {
        let active = ActiveIps::new(60, 1024);
        let t0 = Instant::now();
        assert!(!active.is_active_at(ip(1), t0));
        active.mark(ip(1));
        assert!(active.is_active_at(ip(1), t0));
        assert!(!active.is_active_at(ip(2), t0));
        assert!(
            !active.is_active_at(ip(1), t0 + Duration::from_secs(61)),
            "active entry should expire after the TTL"
        );
    }
}
