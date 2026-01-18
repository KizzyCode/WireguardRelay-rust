//! Orchestrator to run all serial tests in-order

mod utils;

use hex_literal::hex;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;
use wgproxy::config::Config;

mod session {
    include!("./serial/session.rs");
}

#[test]
fn all() {
    /// The testing public key
    const WGPROXY_PUBKEY: [u8; 32] = hex!("4B6172696E6D6167656E20 4B6172696E6D6167656E20 4B6172696E6D6167656E");
    /// The inbound port (this must be unique for each test file to avoid conflicts)
    const WGPROXY_PORT: u16 = 60000;

    // Setup addresses and sockets
    let server = UdpSocket::bind("127.0.0.1:0").expect("failed to create server socket");
    let server_address = server.local_addr().expect("failed to get server socket address");

    // Create config with socket addresses
    let wgproxy = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), WGPROXY_PORT);
    let config = Config {
        WGPROXY_SERVER: server_address.to_string(),
        WGPROXY_PUBKEY,
        WGPROXY_LISTEN: wgproxy,
        WGPROXY_TIMEOUT: Duration::from_secs(3),
        WGPROXY_LOGLEVEL: 1,
    };

    // Boot the relay
    let config_ = config.clone();
    thread::spawn(move || wgproxy::eventloop(config_));
    thread::sleep(Duration::from_secs(3));

    // Execute tests
    dbg!(session::handshake(&server, &wgproxy, &config));
    dbg!(session::handshake2(&server, &wgproxy, &config));
    dbg!(session::timeout(&server, &wgproxy, &config));
    dbg!(session::batch(&server, &wgproxy, &config));
}
