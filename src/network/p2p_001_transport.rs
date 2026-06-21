// ─────────────────────────────────────────────────────────────
// src/network/p2p_001_transport.rs
// ─────────────────────────────────────────────────────────────

use libp2p::{
    PeerId, Transport,
    core::{
        muxing::StreamMuxerBox,
        transport::{Boxed, timeout::TransportTimeout},
        upgrade,
    },
    identity::Keypair,
    noise, tcp, yamux,
};
use std::time::Duration;

/// Defensive, fail-fast limits for the transport layer.
const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(20);

/// Maximum number of concurrent Yamux substreams per connection.
const YAMUX_MAX_NUM_STREAMS: usize = 1024;

/// Maximum receive buffer per substream (bytes).
const YAMUX_MAX_BUFFER_SIZE: usize = 2 * 1024 * 1024;

/// Receive window per substream (bytes).
/// Helps bound per-stream in-flight data and memory pressure.
const YAMUX_RECEIVE_WINDOW_SIZE: u32 = 1024 * 1024;

/// Build a TCP ✕ Noise ✕ Yamux transport.
pub fn build_transport(keypair: Keypair) -> anyhow::Result<Boxed<(PeerId, StreamMuxerBox)>> {
    // Base TCP transport (Tokio)
    let base = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));

    // hard timeout to inbound/outbound connection setup.
    // This prevents connection attempts / upgrades from hanging and consuming resources indefinitely.
    let base = TransportTimeout::new(base, TRANSPORT_TIMEOUT);

    // Configure Yamux defensively (resource caps).
    // These are multiplexing-level limits only.
    let mut yamux_cfg = yamux::Config::default();
    yamux_cfg.set_max_num_streams(YAMUX_MAX_NUM_STREAMS);

    #[allow(deprecated)]
    {
        yamux_cfg.set_max_buffer_size(YAMUX_MAX_BUFFER_SIZE);
        yamux_cfg.set_receive_window_size(YAMUX_RECEIVE_WINDOW_SIZE);
    }

    // Noise-handshake → Yamux-multiplexing → box the whole thing.
    let transport = base
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(&keypair)?)
        .multiplex(yamux_cfg)
        .boxed();

    Ok(transport)
}
