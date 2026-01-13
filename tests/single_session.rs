//! Simple routing for a single `client->server->client` session

mod utils;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::ops::RangeInclusive;
use std::thread;
use std::time::Duration;
use wgproxy::config::Config;

/// The inbound port (this must be unique for each test file to avoid conflicts)
const WGPROXY_PORTS: RangeInclusive<u16> = 60100..=60199;

#[test]
pub fn simple_routing() {
    /// The testing public key
    const WGPROXY_PUBKEY: &[u8; 32] = b"11111111111111111111111111111111";

    // Assemble listening address and buffer
    let wgproxy_listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), WGPROXY_PORTS.skip(0).next().unwrap());
    let handshake = utils::handshake(&WGPROXY_PUBKEY, 0);
    let mut buf = [0; 512];

    // Allocate IPv4 client and IPv6 server socket
    let client = UdpSocket::bind("127.0.0.1:0").expect("failed to create client socket");
    let server = UdpSocket::bind("[::1]:0").expect("failed to create server socket");
    let server_address = server.local_addr().expect("failed to get server socket address");

    // Create config with socket addresses
    let config = Config {
        WGPROXY_SERVER: server_address,
        WGPROXY_PUBKEYS: vec![*WGPROXY_PUBKEY],
        WGPROXY_PORTS,
        WGPROXY_TIMEOUT: Duration::from_secs(180),
        WGPROXY_LOGLEVEL: u8::MAX,
    };

    // Boot relay and give it a few seconds to start up
    thread::spawn(move || wgproxy::eventloop(config));
    thread::sleep(Duration::from_secs(3));

    // Send packet to the server
    client.send_to(&handshake, wgproxy_listen).expect("failed to send test packet");
    let (buf_len, relay_nat_address) = server.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], handshake);

    // Send packet back to the client
    server.send_to(b"TESTOLOPE", relay_nat_address).expect("failed to send test reply");
    let (buf_len, _) = client.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], b"TESTOLOPE");
}
