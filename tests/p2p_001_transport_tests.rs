#![cfg(test)]
#![deny(unsafe_code)]

use futures::{StreamExt, future::try_join_all};
use libp2p::{
    Multiaddr, PeerId, Swarm, identity,
    multiaddr::Protocol,
    ping,
    swarm::{Config as SwarmConfig, SwarmEvent},
};
use remzar::network::p2p_001_transport::build_transport;
use std::{collections::BTreeSet, future::Future, net::TcpListener, time::Duration};

type TestResult<T = ()> = Result<T, String>;

const DEFAULT_TEST_TIMEOUT: Duration = Duration::from_secs(8);
const SHORT_TEST_TIMEOUT: Duration = Duration::from_secs(4);
const PING_INTERVAL: Duration = Duration::from_millis(50);
const PING_TIMEOUT: Duration = Duration::from_secs(2);
const FUZZ_SEED: u64 = 0x9E37_79B9_7F4A_7C15;

struct TestNode {
    peer_id: PeerId,
    swarm: Swarm<ping::Behaviour>,
}

fn fmt_err<E: std::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn run_async<T, F>(future: F) -> TestResult<T>
where
    F: Future<Output = TestResult<T>>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(fmt_err)?;

    runtime.block_on(future)
}

fn make_ping_behaviour() -> ping::Behaviour {
    let cfg = ping::Config::new()
        .with_interval(PING_INTERVAL)
        .with_timeout(PING_TIMEOUT);

    ping::Behaviour::new(cfg)
}

fn p2p_001_transport_has_p2p_protocol(addr: &Multiaddr) -> bool {
    addr.iter()
        .any(|protocol| matches!(protocol, Protocol::P2p(_)))
}

fn p2p_001_transport_has_loopback_ip4(addr: &Multiaddr) -> bool {
    addr.iter().any(|protocol| {
        matches!(
            protocol,
            Protocol::Ip4(ip) if ip == std::net::Ipv4Addr::LOCALHOST
        )
    })
}

fn make_node() -> TestResult<TestNode> {
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());
    let transport = build_transport(keypair).map_err(fmt_err)?;
    let behaviour = make_ping_behaviour();

    let swarm = Swarm::new(
        transport,
        behaviour,
        peer_id,
        SwarmConfig::with_tokio_executor(),
    );

    Ok(TestNode { peer_id, swarm })
}

fn loopback_tcp_zero() -> TestResult<Multiaddr> {
    "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>().map_err(fmt_err)
}

fn closed_loopback_addr() -> TestResult<Multiaddr> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(fmt_err)?;
    let addr = listener.local_addr().map_err(fmt_err)?;
    let port = addr.port();
    drop(listener);

    format!("/ip4/127.0.0.1/tcp/{port}")
        .parse::<Multiaddr>()
        .map_err(fmt_err)
}

fn has_tcp_protocol(addr: &Multiaddr) -> bool {
    addr.iter()
        .any(|protocol| matches!(protocol, Protocol::Tcp(_)))
}

fn append_peer(addr: &Multiaddr, peer: &PeerId) -> TestResult<Multiaddr> {
    format!("{addr}/p2p/{peer}")
        .parse::<Multiaddr>()
        .map_err(fmt_err)
}

fn p2p_001_transport_tcp_port(addr: &Multiaddr) -> TestResult<u16> {
    for protocol in addr.iter() {
        if let Protocol::Tcp(port) = protocol {
            return Ok(port);
        }
    }

    Err("multiaddr did not contain a tcp port".to_string())
}

fn p2p_001_transport_loopback_from_port(port: u16) -> TestResult<Multiaddr> {
    format!("/ip4/127.0.0.1/tcp/{port}")
        .parse::<Multiaddr>()
        .map_err(fmt_err)
}

async fn p2p_001_transport_wait_for_ping_successes(
    first: &mut TestNode,
    second: &mut TestNode,
    target: usize,
) -> TestResult {
    if target == 0usize {
        return Ok(());
    }

    let first_peer = first.peer_id;
    let second_peer = second.peer_id;

    let wait = async {
        let mut successes = 0usize;

        loop {
            tokio::select! {
                event = first.swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(event) = event
                        && event.peer == second_peer
                        && event.result.is_ok()
                    {
                        successes = successes
                            .checked_add(1usize)
                            .ok_or_else(|| "ping success counter overflow".to_string())?;
                    }
                }
                event = second.swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(event) = event
                        && event.peer == first_peer
                        && event.result.is_ok()
                    {
                        successes = successes
                            .checked_add(1usize)
                            .ok_or_else(|| "ping success counter overflow".to_string())?;
                    }
                }
            }

            if successes >= target {
                return Ok(());
            }
        }
    };

    tokio::time::timeout(DEFAULT_TEST_TIMEOUT, wait)
        .await
        .map_err(fmt_err)?
}

fn next_xorshift64(seed: &mut u64) -> u64 {
    let mut x = *seed;
    x ^= x.wrapping_shl(13);
    x ^= x.wrapping_shr(7);
    x ^= x.wrapping_shl(17);
    *seed = x;
    x
}

async fn listen_on_loopback(node: &mut TestNode) -> TestResult<Multiaddr> {
    let listen_addr = loopback_tcp_zero()?;
    let _listener_id = node.swarm.listen_on(listen_addr).map_err(fmt_err)?;

    let wait_for_addr = async {
        loop {
            match node.swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => return Ok(address),
                SwarmEvent::IncomingConnectionError { error, .. } => {
                    return Err(format!(
                        "incoming connection failed while opening listener: {error:?}"
                    ));
                }
                _ => {}
            }
        }
    };

    tokio::time::timeout(DEFAULT_TEST_TIMEOUT, wait_for_addr)
        .await
        .map_err(fmt_err)?
}

async fn wait_for_ping_between(dialer: &mut TestNode, listener: &mut TestNode) -> TestResult {
    let dialer_peer = dialer.peer_id;
    let listener_peer = listener.peer_id;

    let wait = async {
        let mut dialer_established = false;
        let mut listener_established = false;
        let mut ping_seen = false;

        loop {
            tokio::select! {
                event = dialer.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. }
                            if peer_id == listener_peer =>
                        {
                            dialer_established = true;
                        }
                        SwarmEvent::Behaviour(event)
                            if event.peer == listener_peer && event.result.is_ok() =>
                        {
                            ping_seen = true;
                        }
                        SwarmEvent::OutgoingConnectionError { .. } => {}
                        _ => {}
                    }
                }
                event = listener.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. }
                            if peer_id == dialer_peer =>
                        {
                            listener_established = true;
                        }
                        SwarmEvent::Behaviour(event)
                            if event.peer == dialer_peer && event.result.is_ok() =>
                        {
                            ping_seen = true;
                        }
                        SwarmEvent::IncomingConnectionError { .. } => {}
                        _ => {}
                    }
                }
            }

            if dialer_established && listener_established && ping_seen {
                return Ok(());
            }
        }
    };

    tokio::time::timeout(DEFAULT_TEST_TIMEOUT, wait)
        .await
        .map_err(fmt_err)?
}

async fn dial_addr_and_wait_ping(
    dialer: &mut TestNode,
    listener: &mut TestNode,
    addr: Multiaddr,
) -> TestResult {
    dialer.swarm.dial(addr).map_err(fmt_err)?;
    wait_for_ping_between(dialer, listener).await
}

async fn connect_pair() -> TestResult<(TestNode, TestNode)> {
    let mut dialer = make_node()?;
    let mut listener = make_node()?;
    let addr = listen_on_loopback(&mut listener).await?;

    dial_addr_and_wait_ping(&mut dialer, &mut listener, addr).await?;

    Ok((dialer, listener))
}

async fn dial_must_fail(node: &mut TestNode, addr: Multiaddr) -> TestResult {
    match node.swarm.dial(addr) {
        Ok(()) => {
            let wait = async {
                loop {
                    match node.swarm.select_next_some().await {
                        SwarmEvent::OutgoingConnectionError { .. }
                        | SwarmEvent::IncomingConnectionError { .. } => return Ok(()),
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            return Err(format!(
                                "dial unexpectedly established a connection with {peer_id}"
                            ));
                        }
                        _ => {}
                    }
                }
            };

            tokio::time::timeout(SHORT_TEST_TIMEOUT, wait)
                .await
                .map_err(fmt_err)?
        }
        Err(_) => Ok(()),
    }
}

async fn dial_wrong_peer_must_fail(
    dialer: &mut TestNode,
    listener: &mut TestNode,
    addr: Multiaddr,
) -> TestResult {
    dialer.swarm.dial(addr).map_err(fmt_err)?;

    let wait = async {
        loop {
            tokio::select! {
                event = dialer.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::OutgoingConnectionError { .. } => {
                            return Ok(());
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            return Err(format!(
                                "wrong-peer dial unexpectedly established on dialer with {peer_id}"
                            ));
                        }
                        _ => {}
                    }
                }
                event = listener.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::IncomingConnectionError { .. }
                        | SwarmEvent::ConnectionClosed { .. }
                        | SwarmEvent::ConnectionEstablished { .. }
                        | SwarmEvent::Behaviour(_) => {}
                        _ => {}
                    }
                }
            }
        }
    };

    tokio::time::timeout(DEFAULT_TEST_TIMEOUT, wait)
        .await
        .map_err(fmt_err)?
}

#[test]
fn p2p_01_001_transport_builds_one_ed25519_transport() -> TestResult {
    let keypair = identity::Keypair::generate_ed25519();
    let transport = build_transport(keypair).map_err(fmt_err)?;
    drop(transport);
    Ok(())
}

#[test]
fn p2p_02_001_transport_builds_boxed_output_type() -> TestResult {
    let keypair = identity::Keypair::generate_ed25519();
    let transport: libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)> =
        build_transport(keypair).map_err(fmt_err)?;

    drop(transport);
    Ok(())
}

#[test]
fn p2p_03_001_transport_peer_id_from_key_public_before_build_is_valid() -> TestResult {
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());
    let peer_text = peer_id.to_string();

    let transport = build_transport(keypair).map_err(fmt_err)?;
    drop(transport);

    assert!(!peer_text.is_empty());
    Ok(())
}

#[test]
fn p2p_04_001_transport_builds_many_unique_keypairs() -> TestResult {
    let mut peer_ids = BTreeSet::new();

    for _ in 0..24 {
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let inserted = peer_ids.insert(peer_id.to_string());

        let transport = build_transport(keypair).map_err(fmt_err)?;
        drop(transport);

        assert!(inserted);
    }

    assert_eq!(peer_ids.len(), 24);
    Ok(())
}

#[test]
fn p2p_05_001_transport_rejects_unsupported_memory_addr() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let addr = "/memory/12345".parse::<Multiaddr>().map_err(fmt_err)?;
        dial_must_fail(&mut node, addr).await
    })
}

#[test]
fn p2p_06_001_transport_listens_on_loopback_ephemeral_tcp() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let addr = listen_on_loopback(&mut node).await?;

        assert!(addr.to_string().starts_with("/ip4/127.0.0.1/tcp/"));
        Ok(())
    })
}

#[test]
fn p2p_07_001_transport_listen_address_reports_tcp_protocol() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let addr = listen_on_loopback(&mut node).await?;

        assert!(has_tcp_protocol(&addr));
        Ok(())
    })
}

#[test]
fn p2p_08_001_transport_single_dialer_connects_to_listener() -> TestResult {
    run_async(async {
        let (_dialer, _listener) = connect_pair().await?;
        Ok(())
    })
}

#[test]
fn p2p_09_001_transport_listener_can_dial_back_to_dialer() -> TestResult {
    run_async(async {
        let mut first = make_node()?;
        let mut second = make_node()?;

        let first_addr = listen_on_loopback(&mut first).await?;
        dial_addr_and_wait_ping(&mut second, &mut first, first_addr).await?;

        let second_addr = listen_on_loopback(&mut second).await?;
        dial_addr_and_wait_ping(&mut first, &mut second, second_addr).await?;

        Ok(())
    })
}

#[test]
fn p2p_10_001_transport_ping_succeeds_after_handshake() -> TestResult {
    run_async(async {
        let (dialer, listener) = connect_pair().await?;

        assert_ne!(dialer.peer_id, listener.peer_id);
        Ok(())
    })
}

#[test]
fn p2p_11_001_transport_two_sequential_pairs_connect() -> TestResult {
    run_async(async {
        for _ in 0..2 {
            let (_dialer, _listener) = connect_pair().await?;
        }

        Ok(())
    })
}

#[test]
fn p2p_12_001_transport_three_sequential_pairs_connect() -> TestResult {
    run_async(async {
        for _ in 0..3 {
            let (_dialer, _listener) = connect_pair().await?;
        }

        Ok(())
    })
}

#[test]
fn p2p_13_001_transport_one_dialer_connects_to_two_listeners() -> TestResult {
    run_async(async {
        let mut dialer = make_node()?;
        let mut listener_a = make_node()?;
        let mut listener_b = make_node()?;

        let addr_a = listen_on_loopback(&mut listener_a).await?;
        let addr_b = listen_on_loopback(&mut listener_b).await?;

        dial_addr_and_wait_ping(&mut dialer, &mut listener_a, addr_a).await?;
        dial_addr_and_wait_ping(&mut dialer, &mut listener_b, addr_b).await?;

        Ok(())
    })
}

#[test]
fn p2p_14_001_transport_two_dialers_connect_to_one_listener() -> TestResult {
    run_async(async {
        let mut listener = make_node()?;
        let mut dialer_a = make_node()?;
        let mut dialer_b = make_node()?;

        let addr = listen_on_loopback(&mut listener).await?;

        dial_addr_and_wait_ping(&mut dialer_a, &mut listener, addr.clone()).await?;
        dial_addr_and_wait_ping(&mut dialer_b, &mut listener, addr).await?;

        Ok(())
    })
}

#[test]
fn p2p_15_001_transport_repeated_listen_on_same_swarm_two_addrs() -> TestResult {
    run_async(async {
        let mut node = make_node()?;

        let first = listen_on_loopback(&mut node).await?;
        let second = listen_on_loopback(&mut node).await?;

        assert_ne!(first, second);
        assert!(has_tcp_protocol(&first));
        assert!(has_tcp_protocol(&second));
        Ok(())
    })
}

#[test]
fn p2p_16_001_transport_wrong_peer_id_is_rejected() -> TestResult {
    run_async(async {
        let mut dialer = make_node()?;
        let mut listener = make_node()?;
        let wrong_keypair = identity::Keypair::generate_ed25519();
        let wrong_peer = PeerId::from(wrong_keypair.public());

        let addr = listen_on_loopback(&mut listener).await?;
        let wrong_addr = append_peer(&addr, &wrong_peer)?;

        dial_wrong_peer_must_fail(&mut dialer, &mut listener, wrong_addr).await
    })
}

#[test]
fn p2p_17_001_transport_dial_closed_port_errors() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let addr = closed_loopback_addr()?;
        dial_must_fail(&mut node, addr).await
    })
}

#[test]
fn p2p_18_001_transport_malformed_addr_parse_is_rejected() -> TestResult {
    let malformed = "/ip4/127.0.0.1/tcp/not-a-port";
    let parsed = malformed.parse::<Multiaddr>();

    assert!(parsed.is_err());
    Ok(())
}

#[test]
fn p2p_19_001_transport_udp_addr_dial_fails_cleanly() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let addr = "/ip4/127.0.0.1/udp/4444"
            .parse::<Multiaddr>()
            .map_err(fmt_err)?;

        dial_must_fail(&mut node, addr).await
    })
}

#[test]
fn p2p_20_001_transport_peer_ids_property_no_collisions_32() -> TestResult {
    let mut peer_ids = BTreeSet::new();

    for _ in 0..32 {
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let inserted = peer_ids.insert(peer_id.to_string());

        assert!(inserted);

        let transport = build_transport(keypair).map_err(fmt_err)?;
        drop(transport);
    }

    assert_eq!(peer_ids.len(), 32);
    Ok(())
}

#[test]
fn p2p_21_001_transport_build_property_peer_id_text_non_empty_32() -> TestResult {
    for _ in 0..32 {
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());

        assert!(!peer_id.to_string().is_empty());

        let transport = build_transport(keypair).map_err(fmt_err)?;
        drop(transport);
    }

    Ok(())
}

#[test]
fn p2p_22_001_transport_fuzz_build_48_keypairs() -> TestResult {
    let mut built = 0usize;

    for _ in 0..48 {
        let keypair = identity::Keypair::generate_ed25519();
        let transport = build_transport(keypair).map_err(fmt_err)?;
        drop(transport);
        built = built.saturating_add(1);
    }

    assert_eq!(built, 48);
    Ok(())
}

#[test]
fn p2p_23_001_transport_fuzz_listen_connect_six_pairs() -> TestResult {
    run_async(async {
        let mut seed = FUZZ_SEED;
        let mut connections = 0usize;

        for _ in 0..6 {
            let sample = next_xorshift64(&mut seed);

            if (sample & 1) == 0 {
                let (_dialer, _listener) = connect_pair().await?;
            } else {
                let mut listener = make_node()?;
                let mut dialer = make_node()?;
                let addr = listen_on_loopback(&mut listener).await?;
                dial_addr_and_wait_ping(&mut dialer, &mut listener, addr).await?;
            }

            connections = connections.saturating_add(1);
        }

        assert_eq!(connections, 6);
        Ok(())
    })
}

#[test]
fn p2p_24_001_transport_fuzz_alternating_dial_direction() -> TestResult {
    run_async(async {
        let mut seed = FUZZ_SEED;

        for _ in 0..6 {
            let sample = next_xorshift64(&mut seed);
            let mut a = make_node()?;
            let mut b = make_node()?;

            if (sample & 1) == 0 {
                let addr = listen_on_loopback(&mut b).await?;
                dial_addr_and_wait_ping(&mut a, &mut b, addr).await?;
            } else {
                let addr = listen_on_loopback(&mut a).await?;
                dial_addr_and_wait_ping(&mut b, &mut a, addr).await?;
            }
        }

        Ok(())
    })
}

#[test]
fn p2p_25_001_transport_adversarial_duplicate_dials_do_not_break_swarm() -> TestResult {
    run_async(async {
        let mut dialer = make_node()?;
        let mut listener = make_node()?;
        let addr = listen_on_loopback(&mut listener).await?;

        dialer.swarm.dial(addr.clone()).map_err(fmt_err)?;

        match dialer.swarm.dial(addr) {
            Ok(()) | Err(_) => {}
        }

        wait_for_ping_between(&mut dialer, &mut listener).await
    })
}

#[test]
fn p2p_26_001_transport_adversarial_wrong_then_right_peer() -> TestResult {
    run_async(async {
        let mut dialer = make_node()?;
        let mut listener = make_node()?;
        let wrong_keypair = identity::Keypair::generate_ed25519();
        let wrong_peer = PeerId::from(wrong_keypair.public());

        let addr = listen_on_loopback(&mut listener).await?;
        let wrong_addr = append_peer(&addr, &wrong_peer)?;

        dial_wrong_peer_must_fail(&mut dialer, &mut listener, wrong_addr).await?;
        dial_addr_and_wait_ping(&mut dialer, &mut listener, addr).await
    })
}

#[test]
fn p2p_27_001_transport_adversarial_bad_then_good_dial() -> TestResult {
    run_async(async {
        let mut dialer = make_node()?;
        let mut listener = make_node()?;

        let bad_addr = "/ip4/127.0.0.1/udp/5555"
            .parse::<Multiaddr>()
            .map_err(fmt_err)?;
        dial_must_fail(&mut dialer, bad_addr).await?;

        let good_addr = listen_on_loopback(&mut listener).await?;
        dial_addr_and_wait_ping(&mut dialer, &mut listener, good_addr).await
    })
}

#[test]
fn p2p_28_001_transport_adversarial_self_dial_is_rejected() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let addr = listen_on_loopback(&mut node).await?;
        let self_addr = append_peer(&addr, &node.peer_id)?;

        dial_must_fail(&mut node, self_addr).await
    })
}

#[test]
fn p2p_29_001_transport_load_build_128_transports() -> TestResult {
    let mut built = 0usize;

    for _ in 0..128 {
        let keypair = identity::Keypair::generate_ed25519();
        let transport = build_transport(keypair).map_err(fmt_err)?;
        drop(transport);
        built = built.saturating_add(1);
    }

    assert_eq!(built, 128);
    Ok(())
}

#[test]
fn p2p_30_001_transport_load_connect_8_pairs() -> TestResult {
    run_async(async {
        let mut connected = 0usize;

        for _ in 0..8 {
            let (_dialer, _listener) = connect_pair().await?;
            connected = connected.saturating_add(1);
        }

        assert_eq!(connected, 8);
        Ok(())
    })
}

#[test]
fn p2p_31_001_transport_load_one_listener_8_dialers() -> TestResult {
    run_async(async {
        let mut listener = make_node()?;
        let addr = listen_on_loopback(&mut listener).await?;
        let mut dialers = Vec::new();

        for _ in 0..8 {
            let mut dialer = make_node()?;
            dial_addr_and_wait_ping(&mut dialer, &mut listener, addr.clone()).await?;
            dialers.push(dialer);
        }

        assert_eq!(dialers.len(), 8);
        Ok(())
    })
}

#[test]
fn p2p_32_001_transport_load_chain_5_nodes() -> TestResult {
    run_async(async {
        let mut nodes = Vec::new();
        let mut addrs = Vec::new();

        for _ in 0usize..5usize {
            let mut node = make_node()?;
            let addr = listen_on_loopback(&mut node).await?;
            addrs.push(addr);
            nodes.push(node);
        }

        for index in 0usize..4usize {
            let next_index = index
                .checked_add(1usize)
                .ok_or_else(|| "chain index overflow".to_string())?;

            let addr = addrs
                .get(next_index)
                .cloned()
                .ok_or_else(|| "missing chain address".to_string())?;

            let (left, right) = nodes.split_at_mut(next_index);

            let dialer = left
                .get_mut(index)
                .ok_or_else(|| "missing chain dialer".to_string())?;

            let listener = right
                .get_mut(0usize)
                .ok_or_else(|| "missing chain listener".to_string())?;

            dial_addr_and_wait_ping(dialer, listener, addr).await?;
        }

        assert_eq!(nodes.len(), 5usize);
        Ok(())
    })
}

#[test]
fn p2p_33_001_transport_parallel_build_tasks_16() -> TestResult {
    run_async(async {
        let mut handles = Vec::new();

        for _ in 0..16 {
            handles.push(tokio::task::spawn_blocking(|| -> TestResult {
                let keypair = identity::Keypair::generate_ed25519();
                let transport = build_transport(keypair).map_err(fmt_err)?;
                drop(transport);
                Ok(())
            }));
        }

        for handle in handles {
            handle.await.map_err(fmt_err)??;
        }

        Ok(())
    })
}

#[test]
fn p2p_34_001_transport_concurrent_network_pairs_4() -> TestResult {
    run_async(async {
        let mut futures = Vec::new();

        for _ in 0..4 {
            futures.push(async {
                let (_dialer, _listener) = connect_pair().await?;
                Ok::<(), String>(())
            });
        }

        let results = try_join_all(futures).await?;
        assert_eq!(results.len(), 4);
        Ok(())
    })
}

#[test]
fn p2p_35_001_transport_listen_then_drop_does_not_poison_next_transport() -> TestResult {
    run_async(async {
        {
            let mut first = make_node()?;
            let addr = listen_on_loopback(&mut first).await?;
            assert!(has_tcp_protocol(&addr));
        }

        let mut second = make_node()?;
        let addr = listen_on_loopback(&mut second).await?;

        assert!(has_tcp_protocol(&addr));
        Ok(())
    })
}

#[test]
fn p2p_36_001_transport_many_listeners_have_distinct_ports() -> TestResult {
    run_async(async {
        let mut nodes = Vec::new();
        let mut addrs = BTreeSet::new();

        for _ in 0..8 {
            let mut node = make_node()?;
            let addr = listen_on_loopback(&mut node).await?;
            let inserted = addrs.insert(addr.to_string());

            assert!(inserted);

            nodes.push(node);
        }

        assert_eq!(nodes.len(), 8);
        assert_eq!(addrs.len(), 8);
        Ok(())
    })
}

#[test]
fn p2p_37_001_transport_vector_loopback_ipv4_tcp_zero_is_accepted_for_listen() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let addr = loopback_tcp_zero()?;

        let _listener_id = node.swarm.listen_on(addr).map_err(fmt_err)?;

        let observed = tokio::time::timeout(DEFAULT_TEST_TIMEOUT, async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } =
                    node.swarm.select_next_some().await
                {
                    return Ok::<Multiaddr, String>(address);
                }
            }
        })
        .await
        .map_err(fmt_err)??;

        assert!(observed.to_string().starts_with("/ip4/127.0.0.1/tcp/"));
        Ok(())
    })
}

#[test]
fn p2p_38_001_transport_vector_invalid_ip_addr_parse_is_rejected() -> TestResult {
    let invalid = "/ip4/999.999.999.999/tcp/4001";
    let parsed = invalid.parse::<Multiaddr>();

    assert!(parsed.is_err());
    Ok(())
}

#[test]
fn p2p_39_001_transport_property_multiple_nodes_all_peer_ids_distinct() -> TestResult {
    let mut peer_ids = BTreeSet::new();
    let mut nodes = Vec::new();

    for _ in 0..16 {
        let node = make_node()?;
        let inserted = peer_ids.insert(node.peer_id.to_string());

        assert!(inserted);

        nodes.push(node);
    }

    assert_eq!(nodes.len(), 16);
    assert_eq!(peer_ids.len(), 16);
    Ok(())
}

#[test]
fn p2p_40_001_transport_stress_connect_disconnect_6_pairs() -> TestResult {
    run_async(async {
        for _ in 0..6 {
            let (dialer, listener) = connect_pair().await?;
            assert_ne!(dialer.peer_id, listener.peer_id);
            drop(dialer);
            drop(listener);
        }

        Ok(())
    })
}

#[test]
fn p2p_41_001_transport_connects_with_explicit_correct_peer_id() -> TestResult {
    run_async(async {
        let mut dialer = make_node()?;
        let mut listener = make_node()?;

        let addr = listen_on_loopback(&mut listener).await?;
        let addr_with_peer = append_peer(&addr, &listener.peer_id)?;

        dial_addr_and_wait_ping(&mut dialer, &mut listener, addr_with_peer).await
    })
}

#[test]
fn p2p_42_001_transport_correct_peer_multiaddr_contains_expected_peer_text() -> TestResult {
    run_async(async {
        let mut dialer = make_node()?;
        let mut listener = make_node()?;

        let addr = listen_on_loopback(&mut listener).await?;
        let addr_with_peer = append_peer(&addr, &listener.peer_id)?;
        let addr_text = addr_with_peer.to_string();
        let peer_text = listener.peer_id.to_string();

        assert!(addr_text.contains(&peer_text));

        dial_addr_and_wait_ping(&mut dialer, &mut listener, addr_with_peer).await
    })
}

#[test]
fn p2p_43_001_transport_ephemeral_listen_port_is_nonzero() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let addr = listen_on_loopback(&mut node).await?;
        let port = p2p_001_transport_tcp_port(&addr)?;

        assert_ne!(port, 0u16);
        Ok(())
    })
}

#[test]
fn p2p_44_001_transport_two_listen_ports_on_same_swarm_are_distinct() -> TestResult {
    run_async(async {
        let mut node = make_node()?;

        let first = listen_on_loopback(&mut node).await?;
        let second = listen_on_loopback(&mut node).await?;

        let first_port = p2p_001_transport_tcp_port(&first)?;
        let second_port = p2p_001_transport_tcp_port(&second)?;

        assert_ne!(first_port, 0u16);
        assert_ne!(second_port, 0u16);
        assert_ne!(first_port, second_port);
        Ok(())
    })
}

#[test]
fn p2p_45_001_transport_three_listen_ports_on_same_swarm_are_unique() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let mut ports = BTreeSet::new();

        for _ in 0usize..3usize {
            let addr = listen_on_loopback(&mut node).await?;
            let port = p2p_001_transport_tcp_port(&addr)?;
            let inserted = ports.insert(port);

            assert!(inserted);
        }

        assert_eq!(ports.len(), 3usize);
        Ok(())
    })
}

#[test]
fn p2p_46_001_transport_closed_port_with_peer_id_fails_cleanly() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let wrong_keypair = identity::Keypair::generate_ed25519();
        let wrong_peer = PeerId::from(wrong_keypair.public());
        let closed = closed_loopback_addr()?;
        let closed_with_peer = append_peer(&closed, &wrong_peer)?;

        dial_must_fail(&mut node, closed_with_peer).await
    })
}

#[test]
fn p2p_47_001_transport_repeated_closed_port_dials_fail_cleanly() -> TestResult {
    run_async(async {
        let mut node = make_node()?;

        for _ in 0usize..4usize {
            let addr = closed_loopback_addr()?;
            dial_must_fail(&mut node, addr).await?;
        }

        Ok(())
    })
}

#[test]
fn p2p_48_001_transport_memory_addr_with_peer_id_is_rejected() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let keypair = identity::Keypair::generate_ed25519();
        let peer = PeerId::from(keypair.public());
        let memory_addr = "/memory/987654".parse::<Multiaddr>().map_err(fmt_err)?;
        let memory_with_peer = append_peer(&memory_addr, &peer)?;

        dial_must_fail(&mut node, memory_with_peer).await
    })
}

#[test]
fn p2p_49_001_transport_concurrent_correct_peer_pairs_4() -> TestResult {
    run_async(async {
        let mut futures = Vec::new();

        for _ in 0usize..4usize {
            futures.push(async {
                let mut dialer = make_node()?;
                let mut listener = make_node()?;
                let addr = listen_on_loopback(&mut listener).await?;
                let addr_with_peer = append_peer(&addr, &listener.peer_id)?;

                dial_addr_and_wait_ping(&mut dialer, &mut listener, addr_with_peer).await
            });
        }

        let results = try_join_all(futures).await?;
        assert_eq!(results.len(), 4usize);
        Ok(())
    })
}

#[test]
fn p2p_50_001_transport_sequential_correct_peer_id_pairs_5() -> TestResult {
    run_async(async {
        let mut connected = 0usize;

        for _ in 0usize..5usize {
            let mut dialer = make_node()?;
            let mut listener = make_node()?;
            let addr = listen_on_loopback(&mut listener).await?;
            let addr_with_peer = append_peer(&addr, &listener.peer_id)?;

            dial_addr_and_wait_ping(&mut dialer, &mut listener, addr_with_peer).await?;
            connected = connected
                .checked_add(1usize)
                .ok_or_else(|| "connection counter overflow".to_string())?;
        }

        assert_eq!(connected, 5usize);
        Ok(())
    })
}

#[test]
fn p2p_51_001_transport_simultaneous_bidirectional_bare_dials_work() -> TestResult {
    run_async(async {
        let mut first = make_node()?;
        let mut second = make_node()?;

        let first_addr = listen_on_loopback(&mut first).await?;
        let second_addr = listen_on_loopback(&mut second).await?;

        first.swarm.dial(second_addr).map_err(fmt_err)?;
        second.swarm.dial(first_addr).map_err(fmt_err)?;

        wait_for_ping_between(&mut first, &mut second).await
    })
}

#[test]
fn p2p_52_001_transport_simultaneous_bidirectional_peer_id_dials_work() -> TestResult {
    run_async(async {
        let mut first = make_node()?;
        let mut second = make_node()?;

        let first_addr = listen_on_loopback(&mut first).await?;
        let second_addr = listen_on_loopback(&mut second).await?;

        let first_with_peer = append_peer(&first_addr, &first.peer_id)?;
        let second_with_peer = append_peer(&second_addr, &second.peer_id)?;

        first.swarm.dial(second_with_peer).map_err(fmt_err)?;
        second.swarm.dial(first_with_peer).map_err(fmt_err)?;

        wait_for_ping_between(&mut first, &mut second).await
    })
}

#[test]
fn p2p_53_001_transport_second_listen_address_on_each_node_can_connect() -> TestResult {
    run_async(async {
        let mut first = make_node()?;
        let mut second = make_node()?;

        let _first_primary = listen_on_loopback(&mut first).await?;
        let first_secondary = listen_on_loopback(&mut first).await?;

        let _second_primary = listen_on_loopback(&mut second).await?;
        let second_secondary = listen_on_loopback(&mut second).await?;

        first.swarm.dial(second_secondary).map_err(fmt_err)?;
        second.swarm.dial(first_secondary).map_err(fmt_err)?;

        wait_for_ping_between(&mut first, &mut second).await
    })
}

#[test]
fn p2p_54_001_transport_three_dialers_can_use_three_listener_addresses() -> TestResult {
    run_async(async {
        let mut listener = make_node()?;
        let mut addrs = Vec::new();

        for _ in 0usize..3usize {
            addrs.push(listen_on_loopback(&mut listener).await?);
        }

        let mut dialers = Vec::new();

        for addr in addrs {
            let mut dialer = make_node()?;
            dial_addr_and_wait_ping(&mut dialer, &mut listener, addr).await?;
            dialers.push(dialer);
        }

        assert_eq!(dialers.len(), 3usize);
        Ok(())
    })
}

#[test]
fn p2p_55_001_transport_property_twelve_live_listeners_have_unique_ports() -> TestResult {
    run_async(async {
        let mut nodes = Vec::new();
        let mut ports = BTreeSet::new();

        for _ in 0usize..12usize {
            let mut node = make_node()?;
            let addr = listen_on_loopback(&mut node).await?;
            let port = p2p_001_transport_tcp_port(&addr)?;
            let inserted = ports.insert(port);

            assert!(inserted);

            nodes.push(node);
        }

        assert_eq!(nodes.len(), 12usize);
        assert_eq!(ports.len(), 12usize);
        Ok(())
    })
}

#[test]
fn p2p_56_001_transport_property_peer_id_stays_stable_after_connect() -> TestResult {
    run_async(async {
        let mut dialer = make_node()?;
        let mut listener = make_node()?;

        let dialer_peer_before = dialer.peer_id;
        let listener_peer_before = listener.peer_id;

        let addr = listen_on_loopback(&mut listener).await?;
        dial_addr_and_wait_ping(&mut dialer, &mut listener, addr).await?;

        assert_eq!(dialer.peer_id, dialer_peer_before);
        assert_eq!(listener.peer_id, listener_peer_before);
        Ok(())
    })
}

#[test]
fn p2p_57_001_transport_fuzz_closed_ports_fail_without_poisoning_node() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let mut seed = FUZZ_SEED;

        for _ in 0usize..6usize {
            let _sample = next_xorshift64(&mut seed);
            let addr = closed_loopback_addr()?;
            dial_must_fail(&mut node, addr).await?;
        }

        let keypair = identity::Keypair::generate_ed25519();
        let transport = build_transport(keypair).map_err(fmt_err)?;
        drop(transport);

        Ok(())
    })
}

#[test]
fn p2p_58_001_transport_fuzz_alternates_bare_and_peer_id_dials() -> TestResult {
    run_async(async {
        let mut seed = FUZZ_SEED;

        for _ in 0usize..8usize {
            let sample = next_xorshift64(&mut seed);
            let mut dialer = make_node()?;
            let mut listener = make_node()?;
            let addr = listen_on_loopback(&mut listener).await?;

            if (sample & 1u64) == 0u64 {
                dial_addr_and_wait_ping(&mut dialer, &mut listener, addr).await?;
            } else {
                let addr_with_peer = append_peer(&addr, &listener.peer_id)?;
                dial_addr_and_wait_ping(&mut dialer, &mut listener, addr_with_peer).await?;
            }
        }

        Ok(())
    })
}

#[test]
fn p2p_59_001_transport_adversarial_wrong_peer_rejected_three_times() -> TestResult {
    run_async(async {
        for _ in 0usize..3usize {
            let mut dialer = make_node()?;
            let mut listener = make_node()?;

            let wrong_keypair = identity::Keypair::generate_ed25519();
            let wrong_peer = PeerId::from(wrong_keypair.public());

            let addr = listen_on_loopback(&mut listener).await?;
            let wrong_addr = append_peer(&addr, &wrong_peer)?;

            dial_wrong_peer_must_fail(&mut dialer, &mut listener, wrong_addr).await?;
        }

        Ok(())
    })
}

#[test]
fn p2p_60_001_transport_vector_malformed_tcp_multiaddrs_are_rejected() -> TestResult {
    let cases = [
        "/ip4/127.0.0.1/tcp/notaport",
        "/ip4/127.0.0.1/tcp/65536",
        "/ip4/127.0.0.1/tcp/-1",
        "/ip4/abc/tcp/4001",
        "/ip4/127.0.0.1/tcp/",
    ];

    let mut rejected = 0usize;

    for case in cases {
        if case.parse::<Multiaddr>().is_err() {
            rejected = rejected
                .checked_add(1usize)
                .ok_or_else(|| "rejected counter overflow".to_string())?;
        }
    }

    assert_eq!(rejected, cases.len());
    Ok(())
}

#[test]
fn p2p_61_001_transport_edge_dial_tcp_port_zero_fails() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let addr = "/ip4/127.0.0.1/tcp/0"
            .parse::<Multiaddr>()
            .map_err(fmt_err)?;

        dial_must_fail(&mut node, addr).await
    })
}

#[test]
fn p2p_62_001_transport_load_build_256_transports() -> TestResult {
    let mut built = 0usize;

    for _ in 0usize..256usize {
        let keypair = identity::Keypair::generate_ed25519();
        let transport = build_transport(keypair).map_err(fmt_err)?;
        drop(transport);

        built = built
            .checked_add(1usize)
            .ok_or_else(|| "build counter overflow".to_string())?;
    }

    assert_eq!(built, 256usize);
    Ok(())
}

#[test]
fn p2p_63_001_transport_load_connect_10_pairs() -> TestResult {
    run_async(async {
        let mut connected = 0usize;

        for _ in 0usize..10usize {
            let (_dialer, _listener) = connect_pair().await?;
            connected = connected
                .checked_add(1usize)
                .ok_or_else(|| "connected counter overflow".to_string())?;
        }

        assert_eq!(connected, 10usize);
        Ok(())
    })
}

#[test]
fn p2p_64_001_transport_load_one_listener_10_dialers() -> TestResult {
    run_async(async {
        let mut listener = make_node()?;
        let addr = listen_on_loopback(&mut listener).await?;
        let mut dialers = Vec::new();

        for _ in 0usize..10usize {
            let mut dialer = make_node()?;
            dial_addr_and_wait_ping(&mut dialer, &mut listener, addr.clone()).await?;
            dialers.push(dialer);
        }

        assert_eq!(dialers.len(), 10usize);
        Ok(())
    })
}

#[test]
fn p2p_65_001_transport_load_three_listeners_two_dialers_each() -> TestResult {
    run_async(async {
        let mut listeners = Vec::new();
        let mut addrs = Vec::new();

        for _ in 0usize..3usize {
            let mut listener = make_node()?;
            let addr = listen_on_loopback(&mut listener).await?;
            addrs.push(addr);
            listeners.push(listener);
        }

        let mut dialers = Vec::new();

        for listener_index in 0usize..3usize {
            let addr = addrs
                .get(listener_index)
                .cloned()
                .ok_or_else(|| "missing listener address".to_string())?;

            let listener = listeners
                .get_mut(listener_index)
                .ok_or_else(|| "missing listener node".to_string())?;

            for _ in 0usize..2usize {
                let mut dialer = make_node()?;
                dial_addr_and_wait_ping(&mut dialer, listener, addr.clone()).await?;
                dialers.push(dialer);
            }
        }

        assert_eq!(listeners.len(), 3usize);
        assert_eq!(dialers.len(), 6usize);
        Ok(())
    })
}

#[test]
fn p2p_66_001_transport_load_open_and_drop_12_listeners() -> TestResult {
    run_async(async {
        let mut nodes = Vec::new();
        let mut addrs = Vec::new();

        for _ in 0usize..12usize {
            let mut node = make_node()?;
            let addr = listen_on_loopback(&mut node).await?;
            addrs.push(addr);
            nodes.push(node);
        }

        assert_eq!(nodes.len(), 12usize);
        assert_eq!(addrs.len(), 12usize);

        drop(nodes);
        Ok(())
    })
}

#[test]
fn p2p_67_001_transport_property_listen_addr_roundtrips_through_string_parse() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let addr = listen_on_loopback(&mut node).await?;
        let text = addr.to_string();
        let parsed = text.parse::<Multiaddr>().map_err(fmt_err)?;

        assert_eq!(addr, parsed);
        Ok(())
    })
}

#[test]
fn p2p_68_001_transport_property_append_peer_roundtrips_through_string_parse() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let addr = listen_on_loopback(&mut node).await?;
        let addr_with_peer = append_peer(&addr, &node.peer_id)?;
        let text = addr_with_peer.to_string();
        let parsed = text.parse::<Multiaddr>().map_err(fmt_err)?;

        assert_eq!(addr_with_peer, parsed);
        Ok(())
    })
}

#[test]
fn p2p_69_001_transport_vector_correct_peer_multiaddr_connects_after_roundtrip() -> TestResult {
    run_async(async {
        let mut dialer = make_node()?;
        let mut listener = make_node()?;

        let addr = listen_on_loopback(&mut listener).await?;
        let addr_with_peer = append_peer(&addr, &listener.peer_id)?;
        let text = addr_with_peer.to_string();
        let parsed = text.parse::<Multiaddr>().map_err(fmt_err)?;

        dial_addr_and_wait_ping(&mut dialer, &mut listener, parsed).await
    })
}

#[test]
fn p2p_70_001_transport_reconstructed_loopback_addr_from_observed_port_connects() -> TestResult {
    run_async(async {
        let mut dialer = make_node()?;
        let mut listener = make_node()?;

        let observed = listen_on_loopback(&mut listener).await?;
        let port = p2p_001_transport_tcp_port(&observed)?;
        let reconstructed = p2p_001_transport_loopback_from_port(port)?;

        dial_addr_and_wait_ping(&mut dialer, &mut listener, reconstructed).await
    })
}

#[test]
fn p2p_71_001_transport_base_addr_then_peer_addr_both_connect_to_same_listener() -> TestResult {
    run_async(async {
        let mut listener = make_node()?;
        let addr = listen_on_loopback(&mut listener).await?;
        let addr_with_peer = append_peer(&addr, &listener.peer_id)?;

        let mut first_dialer = make_node()?;
        dial_addr_and_wait_ping(&mut first_dialer, &mut listener, addr).await?;

        let mut second_dialer = make_node()?;
        dial_addr_and_wait_ping(&mut second_dialer, &mut listener, addr_with_peer).await?;

        Ok(())
    })
}

#[test]
fn p2p_72_001_transport_second_listener_address_accepts_connection() -> TestResult {
    run_async(async {
        let mut dialer = make_node()?;
        let mut listener = make_node()?;

        let _first_addr = listen_on_loopback(&mut listener).await?;
        let second_addr = listen_on_loopback(&mut listener).await?;

        dial_addr_and_wait_ping(&mut dialer, &mut listener, second_addr).await
    })
}

#[test]
fn p2p_73_001_transport_two_listener_addresses_accept_two_dialers() -> TestResult {
    run_async(async {
        let mut listener = make_node()?;

        let first_addr = listen_on_loopback(&mut listener).await?;
        let second_addr = listen_on_loopback(&mut listener).await?;

        let mut first_dialer = make_node()?;
        let mut second_dialer = make_node()?;

        dial_addr_and_wait_ping(&mut first_dialer, &mut listener, first_addr).await?;
        dial_addr_and_wait_ping(&mut second_dialer, &mut listener, second_addr).await?;

        Ok(())
    })
}

#[test]
fn p2p_74_001_transport_ping_continues_after_initial_handshake() -> TestResult {
    run_async(async {
        let (mut dialer, mut listener) = connect_pair().await?;

        p2p_001_transport_wait_for_ping_successes(&mut dialer, &mut listener, 3usize).await
    })
}

#[test]
fn p2p_75_001_transport_three_independent_pairs_in_one_runtime() -> TestResult {
    run_async(async {
        let mut pairs = Vec::new();

        for _ in 0usize..3usize {
            let pair = connect_pair().await?;
            pairs.push(pair);
        }

        assert_eq!(pairs.len(), 3usize);
        Ok(())
    })
}

#[test]
fn p2p_76_001_transport_build_still_succeeds_after_network_failure() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let closed = closed_loopback_addr()?;

        dial_must_fail(&mut node, closed).await?;

        let keypair = identity::Keypair::generate_ed25519();
        let transport = build_transport(keypair).map_err(fmt_err)?;
        drop(transport);

        Ok(())
    })
}

#[test]
fn p2p_77_001_transport_good_dial_succeeds_after_closed_port_failure() -> TestResult {
    run_async(async {
        let mut dialer = make_node()?;
        let closed = closed_loopback_addr()?;

        dial_must_fail(&mut dialer, closed).await?;

        let mut listener = make_node()?;
        let addr = listen_on_loopback(&mut listener).await?;

        dial_addr_and_wait_ping(&mut dialer, &mut listener, addr).await
    })
}

#[test]
fn p2p_78_001_transport_property_forty_nodes_have_unique_peer_ids() -> TestResult {
    let mut peer_ids = BTreeSet::new();
    let mut nodes = Vec::new();

    for _ in 0usize..40usize {
        let node = make_node()?;
        let inserted = peer_ids.insert(node.peer_id.to_string());

        assert!(inserted);

        nodes.push(node);
    }

    assert_eq!(nodes.len(), 40usize);
    assert_eq!(peer_ids.len(), 40usize);
    Ok(())
}

#[test]
fn p2p_79_001_transport_adversarial_two_wrong_peer_dials_then_good_dial() -> TestResult {
    run_async(async {
        let mut dialer = make_node()?;
        let mut listener = make_node()?;

        let addr = listen_on_loopback(&mut listener).await?;

        for _ in 0usize..2usize {
            let wrong_keypair = identity::Keypair::generate_ed25519();
            let wrong_peer = PeerId::from(wrong_keypair.public());
            let wrong_addr = append_peer(&addr, &wrong_peer)?;

            dial_wrong_peer_must_fail(&mut dialer, &mut listener, wrong_addr).await?;
        }

        dial_addr_and_wait_ping(&mut dialer, &mut listener, addr).await
    })
}

#[test]
fn p2p_80_001_transport_stress_one_dialer_connects_to_12_listeners() -> TestResult {
    run_async(async {
        let mut dialer = make_node()?;
        let mut listeners = Vec::new();
        let mut addrs = Vec::new();

        for _ in 0usize..12usize {
            let mut listener = make_node()?;
            let addr = listen_on_loopback(&mut listener).await?;
            addrs.push(addr);
            listeners.push(listener);
        }

        for listener_index in 0usize..12usize {
            let addr = addrs
                .get(listener_index)
                .cloned()
                .ok_or_else(|| "missing stress listener address".to_string())?;

            let listener = listeners
                .get_mut(listener_index)
                .ok_or_else(|| "missing stress listener".to_string())?;

            dial_addr_and_wait_ping(&mut dialer, listener, addr).await?;
        }

        assert_eq!(listeners.len(), 12usize);
        Ok(())
    })
}

#[test]
fn p2p_81_001_transport_vector_listen_addr_has_ip4_loopback_and_tcp() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let addr = listen_on_loopback(&mut node).await?;

        assert!(p2p_001_transport_has_loopback_ip4(&addr));
        assert!(has_tcp_protocol(&addr));
        Ok(())
    })
}

#[test]
fn p2p_82_001_transport_vector_appended_peer_addr_has_p2p_protocol() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let addr = listen_on_loopback(&mut node).await?;
        let with_peer = append_peer(&addr, &node.peer_id)?;

        assert!(p2p_001_transport_has_p2p_protocol(&with_peer));
        Ok(())
    })
}

#[test]
fn p2p_83_001_transport_vector_invalid_p2p_component_is_rejected() -> TestResult {
    let cases = [
        "/ip4/127.0.0.1/tcp/4001/p2p/not-a-peer-id",
        "/ip4/127.0.0.1/tcp/4001/p2p/",
        "/ip4/127.0.0.1/tcp/4001/p2p/%%%%",
        "/ip4/127.0.0.1/tcp/4001/p2p/123",
    ];

    let mut rejected = 0usize;

    for case in cases {
        if case.parse::<Multiaddr>().is_err() {
            rejected = rejected
                .checked_add(1usize)
                .ok_or_else(|| "invalid p2p rejection counter overflow".to_string())?;
        }
    }

    assert_eq!(rejected, cases.len());
    Ok(())
}

#[test]
fn p2p_84_001_transport_vector_max_tcp_port_parses_and_extracts() -> TestResult {
    let addr = "/ip4/127.0.0.1/tcp/65535"
        .parse::<Multiaddr>()
        .map_err(fmt_err)?;
    let port = p2p_001_transport_tcp_port(&addr)?;

    assert_eq!(port, 65535u16);
    Ok(())
}

#[test]
fn p2p_85_001_transport_vector_min_nonzero_tcp_port_parses_and_extracts() -> TestResult {
    let addr = "/ip4/127.0.0.1/tcp/1"
        .parse::<Multiaddr>()
        .map_err(fmt_err)?;
    let port = p2p_001_transport_tcp_port(&addr)?;

    assert_eq!(port, 1u16);
    Ok(())
}

#[test]
fn p2p_86_001_transport_edge_udp_listen_is_rejected_by_tcp_transport() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let udp_addr = "/ip4/127.0.0.1/udp/0"
            .parse::<Multiaddr>()
            .map_err(fmt_err)?;

        let result = node.swarm.listen_on(udp_addr);

        assert!(result.is_err());
        Ok(())
    })
}

#[test]
fn p2p_87_001_transport_edge_memory_listen_is_rejected_by_tcp_transport() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let memory_addr = "/memory/123456".parse::<Multiaddr>().map_err(fmt_err)?;

        let result = node.swarm.listen_on(memory_addr);

        assert!(result.is_err());
        Ok(())
    })
}

#[test]
fn p2p_88_001_transport_edge_peer_id_text_roundtrips() -> TestResult {
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());
    let peer_text = peer_id.to_string();
    let parsed = peer_text.parse::<PeerId>().map_err(fmt_err)?;

    assert_eq!(peer_id, parsed);

    let transport = build_transport(keypair).map_err(fmt_err)?;
    drop(transport);
    Ok(())
}

#[test]
fn p2p_89_001_transport_edge_appended_peer_roundtrip_preserves_protocols() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let addr = listen_on_loopback(&mut node).await?;
        let with_peer = append_peer(&addr, &node.peer_id)?;
        let text = with_peer.to_string();
        let parsed = text.parse::<Multiaddr>().map_err(fmt_err)?;

        assert_eq!(with_peer, parsed);
        assert!(has_tcp_protocol(&parsed));
        assert!(p2p_001_transport_has_p2p_protocol(&parsed));
        Ok(())
    })
}

#[test]
fn p2p_90_001_transport_edge_reconstructed_addr_keeps_observed_port() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let observed = listen_on_loopback(&mut node).await?;
        let observed_port = p2p_001_transport_tcp_port(&observed)?;
        let reconstructed = p2p_001_transport_loopback_from_port(observed_port)?;
        let reconstructed_port = p2p_001_transport_tcp_port(&reconstructed)?;

        assert_eq!(observed_port, reconstructed_port);
        Ok(())
    })
}

#[test]
fn p2p_91_001_transport_property_correct_peer_dials_six_sequences() -> TestResult {
    run_async(async {
        let mut connected = 0usize;

        for _ in 0usize..6usize {
            let mut dialer = make_node()?;
            let mut listener = make_node()?;
            let addr = listen_on_loopback(&mut listener).await?;
            let with_peer = append_peer(&addr, &listener.peer_id)?;

            dial_addr_and_wait_ping(&mut dialer, &mut listener, with_peer).await?;

            connected = connected
                .checked_add(1usize)
                .ok_or_else(|| "correct peer sequence counter overflow".to_string())?;
        }

        assert_eq!(connected, 6usize);
        Ok(())
    })
}

#[test]
fn p2p_92_001_transport_property_ping_continues_after_peer_id_dial() -> TestResult {
    run_async(async {
        let mut dialer = make_node()?;
        let mut listener = make_node()?;
        let addr = listen_on_loopback(&mut listener).await?;
        let with_peer = append_peer(&addr, &listener.peer_id)?;

        dial_addr_and_wait_ping(&mut dialer, &mut listener, with_peer).await?;
        p2p_001_transport_wait_for_ping_successes(&mut dialer, &mut listener, 4usize).await
    })
}

#[test]
fn p2p_93_001_transport_adversarial_wrong_peer_then_closed_port_then_good_dial() -> TestResult {
    run_async(async {
        let mut dialer = make_node()?;
        let mut listener = make_node()?;
        let addr = listen_on_loopback(&mut listener).await?;

        let wrong_keypair = identity::Keypair::generate_ed25519();
        let wrong_peer = PeerId::from(wrong_keypair.public());
        let wrong_addr = append_peer(&addr, &wrong_peer)?;
        dial_wrong_peer_must_fail(&mut dialer, &mut listener, wrong_addr).await?;

        let closed = closed_loopback_addr()?;
        dial_must_fail(&mut dialer, closed).await?;

        dial_addr_and_wait_ping(&mut dialer, &mut listener, addr).await
    })
}

#[test]
fn p2p_94_001_transport_adversarial_bad_protocols_do_not_poison_build() -> TestResult {
    run_async(async {
        let mut node = make_node()?;

        let bad_addrs = [
            "/ip4/127.0.0.1/udp/7777",
            "/memory/8888",
            "/ip4/127.0.0.1/tcp/0",
        ];

        for bad_addr in bad_addrs {
            let addr = bad_addr.parse::<Multiaddr>().map_err(fmt_err)?;
            dial_must_fail(&mut node, addr).await?;
        }

        let keypair = identity::Keypair::generate_ed25519();
        let transport = build_transport(keypair).map_err(fmt_err)?;
        drop(transport);

        Ok(())
    })
}

#[test]
fn p2p_95_001_transport_load_open_16_listeners_unique_addresses() -> TestResult {
    run_async(async {
        let mut nodes = Vec::new();
        let mut addrs = BTreeSet::new();

        for _ in 0usize..16usize {
            let mut node = make_node()?;
            let addr = listen_on_loopback(&mut node).await?;
            let inserted = addrs.insert(addr.to_string());

            assert!(inserted);

            nodes.push(node);
        }

        assert_eq!(nodes.len(), 16usize);
        assert_eq!(addrs.len(), 16usize);
        Ok(())
    })
}

#[test]
fn p2p_96_001_transport_load_one_listener_six_peer_id_dialers() -> TestResult {
    run_async(async {
        let mut listener = make_node()?;
        let addr = listen_on_loopback(&mut listener).await?;
        let with_peer = append_peer(&addr, &listener.peer_id)?;
        let mut dialers = Vec::new();

        for _ in 0usize..6usize {
            let mut dialer = make_node()?;
            dial_addr_and_wait_ping(&mut dialer, &mut listener, with_peer.clone()).await?;
            dialers.push(dialer);
        }

        assert_eq!(dialers.len(), 6usize);
        Ok(())
    })
}

#[test]
fn p2p_97_001_transport_load_pair_survives_multiple_ping_cycles() -> TestResult {
    run_async(async {
        let (mut dialer, mut listener) = connect_pair().await?;

        p2p_001_transport_wait_for_ping_successes(&mut dialer, &mut listener, 6usize).await
    })
}

#[test]
fn p2p_98_001_transport_vector_peer_multiaddr_text_contains_base_addr_text() -> TestResult {
    run_async(async {
        let mut node = make_node()?;
        let addr = listen_on_loopback(&mut node).await?;
        let with_peer = append_peer(&addr, &node.peer_id)?;

        let addr_text = addr.to_string();
        let peer_addr_text = with_peer.to_string();

        assert!(peer_addr_text.starts_with(&addr_text));
        assert_ne!(addr_text, peer_addr_text);
        Ok(())
    })
}

#[test]
fn p2p_99_001_transport_property_twenty_reconstructed_addrs_roundtrip() -> TestResult {
    run_async(async {
        let mut nodes = Vec::new();
        let mut checked = 0usize;

        for _ in 0usize..20usize {
            let mut node = make_node()?;
            let observed = listen_on_loopback(&mut node).await?;
            let port = p2p_001_transport_tcp_port(&observed)?;
            let reconstructed = p2p_001_transport_loopback_from_port(port)?;
            let reparsed = reconstructed
                .to_string()
                .parse::<Multiaddr>()
                .map_err(fmt_err)?;

            assert_eq!(reconstructed, reparsed);

            checked = checked
                .checked_add(1usize)
                .ok_or_else(|| "roundtrip counter overflow".to_string())?;

            nodes.push(node);
        }

        assert_eq!(nodes.len(), 20usize);
        assert_eq!(checked, 20usize);
        Ok(())
    })
}

#[test]
fn p2p_100_001_transport_end_to_end_four_node_peer_id_chain() -> TestResult {
    run_async(async {
        let mut nodes = Vec::new();
        let mut addrs = Vec::new();

        for _ in 0usize..4usize {
            let mut node = make_node()?;
            let addr = listen_on_loopback(&mut node).await?;
            let with_peer = append_peer(&addr, &node.peer_id)?;

            addrs.push(with_peer);
            nodes.push(node);
        }

        for index in 0usize..3usize {
            let next_index = index
                .checked_add(1usize)
                .ok_or_else(|| "four node chain index overflow".to_string())?;

            let addr = addrs
                .get(next_index)
                .cloned()
                .ok_or_else(|| "missing four node chain address".to_string())?;

            let (left, right) = nodes.split_at_mut(next_index);

            let dialer = left
                .get_mut(index)
                .ok_or_else(|| "missing four node chain dialer".to_string())?;

            let listener = right
                .get_mut(0usize)
                .ok_or_else(|| "missing four node chain listener".to_string())?;

            dial_addr_and_wait_ping(dialer, listener, addr).await?;
        }

        assert_eq!(nodes.len(), 4usize);
        Ok(())
    })
}
