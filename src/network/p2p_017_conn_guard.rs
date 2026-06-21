use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};

/// Conn-guard policy knobs.
#[derive(Debug, Clone)]
pub struct ConnGuardConfig {
    /// Max concurrently *admitted* peers per concrete IP.
    pub max_per_ip: usize,
    /// Max concurrently *admitted* peers per IPv4 /24.
    pub max_per_v4_24: usize,
    /// Max concurrently *admitted* peers per IPv6 /64.
    pub max_per_v6_64: usize,
    /// Max peers allowed in "pending handshake" state at once.
    pub max_handshaking: usize,
    /// How long we give a peer to complete handshake (Version exchange).
    pub handshake_deadline: Duration,
    /// Rate-limit window.
    pub rate_window: Duration,
    /// Max new connection attempts per IP within `rate_window`.
    pub max_new_conns_per_ip_per_window: usize,
}

impl Default for ConnGuardConfig {
    fn default() -> Self {
        Self {
            max_per_ip: 8,
            max_per_v4_24: 32,
            max_per_v6_64: 16,
            max_handshaking: 32,
            handshake_deadline: Duration::from_secs(5),
            rate_window: Duration::from_secs(10),
            max_new_conns_per_ip_per_window: 10,
        }
    }
}

/// The decision returned by the guard for a new connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardDecision {
    Allow,
    Drop(DropReason),
}

/// Why a peer was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    MissingIp,
    RateLimited,
    HandshakePoolFull,
    PerIpCap,
    PerSubnetCap,
    HandshakeDeadlineOverflow,
    CounterOverflow,
}

/// Internal key type for subnet counting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SubnetKey {
    V4_24([u8; 3]),
    V6_64([u8; 8]),
}

/// Tracks per-peer connection multiplicity (libp2p can have multiple conns per PeerId).
#[derive(Debug, Default, Clone)]
struct PeerConnState {
    conns: usize,
    ip: Option<IpAddr>,
    subnet: Option<SubnetKey>,
}

/// Main guard state.
#[derive(Debug)]
pub struct ConnGuard {
    cfg: ConnGuardConfig,

    /// Peers that have completed “admission handshake”.
    admitted: HashSet<PeerId>,

    /// Peers currently handshaking: peer -> deadline.
    pending: HashMap<PeerId, Instant>,

    /// Peer connection states so we can decrement counts on disconnect.
    peer_state: HashMap<PeerId, PeerConnState>,

    /// Counts for *admitted* peers.
    per_ip: HashMap<IpAddr, usize>,
    per_subnet: HashMap<SubnetKey, usize>,

    /// Rate-limit attempts per IP: IP -> timestamps in window.
    recent_attempts: HashMap<IpAddr, VecDeque<Instant>>,
}

impl ConnGuard {
    pub fn new(cfg: ConnGuardConfig) -> Self {
        Self {
            cfg,
            admitted: HashSet::new(),
            pending: HashMap::new(),
            peer_state: HashMap::new(),
            per_ip: HashMap::new(),
            per_subnet: HashMap::new(),
            recent_attempts: HashMap::new(),
        }
    }

    pub fn _cfg(&self) -> &ConnGuardConfig {
        &self.cfg
    }

    /// Extract IP from a libp2p Multiaddr if present.
    pub fn ip_from_multiaddr(addr: &Multiaddr) -> Option<IpAddr> {
        for p in addr.iter() {
            match p {
                Protocol::Ip4(ip) => return Some(IpAddr::V4(ip)),
                Protocol::Ip6(ip) => return Some(IpAddr::V6(ip)),
                _ => {}
            }
        }
        None
    }

    fn subnet_key(ip: IpAddr) -> SubnetKey {
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                SubnetKey::V4_24([o[0], o[1], o[2]])
            }
            IpAddr::V6(v6) => {
                let o = v6.octets();
                SubnetKey::V6_64([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]])
            }
        }
    }

    fn prune_rate_window(queue: &mut VecDeque<Instant>, now: Instant, window: Duration) {
        while let Some(t) = queue.front().copied() {
            if now.duration_since(t) > window {
                queue.pop_front();
            } else {
                break;
            }
        }
    }

    fn checked_inc(map: &mut HashMap<IpAddr, usize>, key: IpAddr) -> Result<(), DropReason> {
        let cur = *map.get(&key).unwrap_or(&0);
        let next = cur.checked_add(1).ok_or(DropReason::CounterOverflow)?;
        map.insert(key, next);
        Ok(())
    }

    fn checked_inc_subnet(
        map: &mut HashMap<SubnetKey, usize>,
        key: SubnetKey,
    ) -> Result<(), DropReason> {
        let cur = *map.get(&key).unwrap_or(&0);
        let next = cur.checked_add(1).ok_or(DropReason::CounterOverflow)?;
        map.insert(key, next);
        Ok(())
    }

    /// Call this when libp2p reports `ConnectionEstablished`.
    pub fn on_connection_established(
        &mut self,
        peer: PeerId,
        remote_addr: &Multiaddr,
        now: Instant,
    ) -> GuardDecision {
        let ip = match Self::ip_from_multiaddr(remote_addr) {
            Some(ip) => ip,
            None => return GuardDecision::Drop(DropReason::MissingIp),
        };

        // Rate-limit attempts per IP (cheap, protects handshake CPU/memory).
        let q = self.recent_attempts.entry(ip).or_default();
        Self::prune_rate_window(q, now, self.cfg.rate_window);
        if q.len() >= self.cfg.max_new_conns_per_ip_per_window {
            return GuardDecision::Drop(DropReason::RateLimited);
        }
        q.push_back(now);

        // Pending handshake pool cap.
        if self.pending.len() >= self.cfg.max_handshaking && !self.pending.contains_key(&peer) {
            return GuardDecision::Drop(DropReason::HandshakePoolFull);
        }

        // Track peer state + multiplicity.
        let st = self.peer_state.entry(peer).or_default();
        st.conns = st.conns.saturating_add(1);
        st.ip = Some(ip);
        st.subnet = Some(Self::subnet_key(ip));

        // Ensure it’s in pending with a deadline (if not already).
        if !self.pending.contains_key(&peer) {
            let deadline = match now.checked_add(self.cfg.handshake_deadline) {
                Some(d) => d,
                None => return GuardDecision::Drop(DropReason::HandshakeDeadlineOverflow),
            };
            self.pending.insert(peer, deadline);
        }

        GuardDecision::Allow
    }

    /// Call to *accept* the peer as admitted (e.g., after Version handshake succeeds).
    pub fn try_admit(&mut self, peer: PeerId) -> GuardDecision {
        if self.admitted.contains(&peer) {
            // Already admitted; make sure it's not pending.
            self.pending.remove(&peer);
            return GuardDecision::Allow;
        }

        let st = match self.peer_state.get(&peer) {
            Some(s) => s.clone(),
            None => return GuardDecision::Drop(DropReason::MissingIp),
        };

        let ip = match st.ip {
            Some(ip) => ip,
            None => return GuardDecision::Drop(DropReason::MissingIp),
        };

        // Per-IP cap.
        let per_ip = *self.per_ip.get(&ip).unwrap_or(&0);
        if per_ip >= self.cfg.max_per_ip {
            return GuardDecision::Drop(DropReason::PerIpCap);
        }

        // Per-subnet cap.
        let sk = match st.subnet {
            Some(sk) => sk,
            None => return GuardDecision::Drop(DropReason::MissingIp),
        };
        let per_sn = *self.per_subnet.get(&sk).unwrap_or(&0);
        let cap = match sk {
            SubnetKey::V4_24(_) => self.cfg.max_per_v4_24,
            SubnetKey::V6_64(_) => self.cfg.max_per_v6_64,
        };
        if per_sn >= cap {
            return GuardDecision::Drop(DropReason::PerSubnetCap);
        }

        // Admit: update sets + counters.
        self.pending.remove(&peer);
        self.admitted.insert(peer);

        if let Err(r) = Self::checked_inc(&mut self.per_ip, ip) {
            // Roll back admission so state stays consistent.
            self.admitted.remove(&peer);
            return GuardDecision::Drop(r);
        }
        if let Err(r) = Self::checked_inc_subnet(&mut self.per_subnet, sk) {
            // Roll back admission + per_ip increment.
            self.admitted.remove(&peer);
            dec_map(&mut self.per_ip, &ip);
            return GuardDecision::Drop(r);
        }

        GuardDecision::Allow
    }

    /// Call this when libp2p reports `ConnectionClosed`.
    pub fn on_connection_closed(&mut self, peer: PeerId) {
        let mut remove_peer_state = false;

        if let Some(st) = self.peer_state.get_mut(&peer) {
            st.conns = st.conns.saturating_sub(1);

            if st.conns == 0 {
                remove_peer_state = true;

                // If admitted, decrement counters.
                if self.admitted.remove(&peer) {
                    if let Some(ip) = st.ip {
                        dec_map(&mut self.per_ip, &ip);
                    }
                    if let Some(sk) = st.subnet {
                        dec_map_subnet(&mut self.per_subnet, &sk);
                    }
                }

                // Always remove pending on full disconnect.
                self.pending.remove(&peer);
            }
        } else {
            // Unknown peer state—still ensure sets cleared.
            self.admitted.remove(&peer);
            self.pending.remove(&peer);
        }

        if remove_peer_state {
            self.peer_state.remove(&peer);
        }
    }

    /// Sweep pending peers whose handshake deadline elapsed.
    pub fn sweep_timeouts(&mut self, now: Instant) -> Vec<PeerId> {
        // Collect keys first (HashSet iteration is also hash-based, so keep it Vec from keys).
        let keys: Vec<PeerId> = self.pending.keys().copied().collect();

        let mut drop: Vec<PeerId> = Vec::new();
        for peer in keys {
            if let Some(&deadline) = self.pending.get(&peer)
                && now > deadline
            {
                drop.push(peer);
            }
        }

        for p in &drop {
            self.pending.remove(p);
        }
        drop
    }

    /// True if peer is admitted.
    pub fn is_admitted(&self, peer: &PeerId) -> bool {
        self.admitted.contains(peer)
    }

    /// For logging/metrics.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn admitted_len(&self) -> usize {
        self.admitted.len()
    }
}

fn dec_map<K: std::hash::Hash + Eq + Copy>(m: &mut HashMap<K, usize>, k: &K) {
    if let Some(v) = m.get_mut(k) {
        *v = v.saturating_sub(1);
        if *v == 0 {
            m.remove(k);
        }
    }
}

fn dec_map_subnet(m: &mut HashMap<SubnetKey, usize>, k: &SubnetKey) {
    if let Some(v) = m.get_mut(k) {
        *v = v.saturating_sub(1);
        if *v == 0 {
            m.remove(k);
        }
    }
}
