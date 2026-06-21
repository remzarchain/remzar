// src/network/p2p_019_inflight_limiter.rs

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use libp2p::PeerId;

#[derive(Debug)]
struct InflightInner {
    per_peer: HashMap<PeerId, u32>,
    global: u32,
}

#[derive(Debug, Clone)]
pub struct InflightLimiter {
    max_per_peer: u32,
    max_global: u32,
    inner: Arc<Mutex<InflightInner>>,
}

#[must_use]
pub struct InflightPermit {
    peer: PeerId,
    inner: Arc<Mutex<InflightInner>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InflightDrop {
    PeerCap,
    GlobalCap,
}

pub enum InflightDecision {
    Allow(InflightPermit),
    Drop(InflightDrop),
}

impl Drop for InflightPermit {
    fn drop(&mut self) {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        if let Some(v) = g.per_peer.get_mut(&self.peer) {
            *v = v.saturating_sub(1);
            if *v == 0 {
                g.per_peer.remove(&self.peer);
            }
        }
        g.global = g.global.saturating_sub(1);
    }
}

impl InflightLimiter {
    pub fn new(max_per_peer: u32, max_global: u32) -> Self {
        Self {
            max_per_peer,
            max_global,
            inner: Arc::new(Mutex::new(InflightInner {
                per_peer: HashMap::new(),
                global: 0,
            })),
        }
    }

    pub fn try_acquire(&self, peer: &PeerId) -> InflightDecision {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        // treat a "saturated" counter as an immediate drop
        // rather than allowing wrap-around via saturating_add().
        if g.global == u32::MAX {
            return InflightDecision::Drop(InflightDrop::GlobalCap);
        }

        let cur_peer = g.per_peer.get(peer).copied().unwrap_or(0);

        if cur_peer >= self.max_per_peer {
            return InflightDecision::Drop(InflightDrop::PeerCap);
        }
        if g.global >= self.max_global {
            return InflightDecision::Drop(InflightDrop::GlobalCap);
        }

        // fail closed if peer counter is saturated.
        if cur_peer == u32::MAX {
            return InflightDecision::Drop(InflightDrop::PeerCap);
        }

        // PeerId is Copy -> use *peer (copies) instead of clone()
        let next_peer = match cur_peer.checked_add(1) {
            Some(v) => v,
            None => return InflightDecision::Drop(InflightDrop::PeerCap),
        };
        g.per_peer.insert(*peer, next_peer);

        let next_global = match g.global.checked_add(1) {
            Some(v) => v,
            None => return InflightDecision::Drop(InflightDrop::GlobalCap),
        };
        g.global = next_global;

        InflightDecision::Allow(InflightPermit {
            peer: *peer,
            inner: Arc::clone(&self.inner),
        })
    }
}
