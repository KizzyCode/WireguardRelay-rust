//! Testing utils

use blake2::digest::Mac;
use blake2::digest::consts::U16;
use blake2::{Blake2s256, Blake2sMac, Digest};
use hex_literal::hex;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::thread;
use std::time::Duration;
use wgproxy::config::Config;

/// The testing public key
pub const WGPROXY_PUBKEY: [u8; 32] = hex!("4B6172696E6D6167656E20 4B6172696E6D6167656E20 4B6172696E6D6167656E");
/// The inbound port (this must be unique for each test file to avoid conflicts)
pub const WGPROXY_BASEPORT: u16 = 60000;

/// Starts a new separate [`wgproxy::eventloop`] session for testing
pub fn session() -> (Config, SocketAddr, UdpSocket) {
    /// Atomic port counter to allocate unique UDP ports
    static PORT_COUNTER: AtomicU16 = AtomicU16::new(WGPROXY_BASEPORT);

    // Setup addresses and sockets
    let server_socket = UdpSocket::bind("127.0.0.1:0").expect("failed to create server socket");
    let server_address = server_socket.local_addr().expect("failed to get server socket address");

    // Create config with socket addresses
    let proxy_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let proxy_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), proxy_port);
    let config = Config {
        WGPROXY_SERVER: server_address.to_string(),
        WGPROXY_PUBKEY,
        WGPROXY_LISTEN: proxy_address,
        WGPROXY_TIMEOUT: Duration::from_secs(3),
        WGPROXY_LOGLEVEL: 1,
    };

    // Boot the relay
    let config_ = config.clone();
    thread::spawn(move || wgproxy::eventloop(config_));
    thread::sleep(Duration::from_secs(3));

    // Return triple
    (config, proxy_address, server_socket)
}

/// Computes a handshake packet
pub fn handshake(public_key: &[u8; 32]) -> [u8; 148] {
    /// A template packet
    const TEMPLATE: [u8; 148] = hex! {
        "01000000"
        "4B6172696E6D6167656E20 4B6172696E6D6167656E20 4B6172696E6D6167656E20 4B6172696E6D6167656E20"
        "4B6172696E6D6167656E20 4B6172696E6D6167656E20 4B6172696E6D6167656E20 4B6172696E6D6167656E20"
        "4B6172696E6D6167656E20 4B6172696E6D6167656E20 5858"
        "58585858585858585858585858585858 00000000000000000000000000000000"
    };

    /// Counter to ensure unique handshakes
    static HANDSHAKE_COUNTER: AtomicU16 = AtomicU16::new(0);

    // Set the packet number
    let mut packet = TEMPLATE;
    let counter = HANDSHAKE_COUNTER.fetch_add(1, Ordering::SeqCst);
    packet[114..116].copy_from_slice(&counter.to_be_bytes());

    // Compute MAC1 over the packet
    let label_pubkey_hash = Blake2s256::new().chain_update(b"mac1----").chain_update(public_key).finalize();
    let mac1 = Blake2sMac::<U16>::new(&label_pubkey_hash).chain_update(&packet[..116]).finalize();

    // Copy MAC1 into packet
    packet[116..132].copy_from_slice(&mac1.into_bytes());
    packet
}
