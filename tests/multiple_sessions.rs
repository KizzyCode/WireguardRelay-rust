//! Interleaved routing for multiple simultaneous `client->server->client` sessions

mod utils;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::ops::RangeInclusive;
use std::time::Duration;
use std::{array, thread};
use wgproxy::config::Config;

/// The inbound port (this must be unique for each test file to avoid conflicts)
const WGPROXY_PORTS: RangeInclusive<u16> = 60000..=60099;

#[test]
pub fn interleaved_routing() {
    /// The testing public key
    const WGPROXY_PUBKEY: &[u8; 32] = b"00000000000000000000000000000000";

    // Assemble listening address and buffer
    let wgproxy_listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), WGPROXY_PORTS.skip(0).next().unwrap());

    // Allocate IPv4 client and IPv6 server socket
    let server = UdpSocket::bind("[::1]:0").expect("failed to create server socket");
    let server_address = server.local_addr().expect("failed to get server socket address");
    let clients: [_; 63] = array::from_fn(|_| UdpSocket::bind("127.0.0.1:0").expect("failed to create client socket"));

    // Create config with socket addresses
    let config = Config {
        WGPROXY_SERVER: server_address,
        WGPROXY_PUBKEYS: vec![*WGPROXY_PUBKEY],
        WGPROXY_PORTS,
        WGPROXY_TIMEOUT: Duration::from_secs(180),
        WGPROXY_LOGLEVEL: u8::MAX,
    };

    // Boot relay and use a scope to ensure real parallelism for reliability
    thread::spawn(move || wgproxy::eventloop(config));
    thread::scope(|scope| {
        // Send packets
        scope.spawn(|| {
            thread::sleep(Duration::from_secs(3));
            for (index, client) in clients.iter().enumerate() {
                // Create and send valid handshakes
                let handshake = utils::handshake(WGPROXY_PUBKEY, index as u16);
                client.send_to(&handshake, wgproxy_listen).expect("failed to send test packet");
            }
        });

        // Reflect packets
        scope.spawn(|| {
            let mut buf = [0; 512];
            for _ in 0..clients.len() {
                // Receive handshake packet
                let (buf_len, relay_nat_address) = server.recv_from(&mut buf).expect("failed to receive test packet");
                assert_eq!(buf_len, 148, "invalid handshake message");

                // Reflect only payload from packet to have a different message
                server.send_to(&buf[4..116], relay_nat_address).expect("failed to send test reply");
            }
        });

        // Expect reflected responses
        let mut buf = [0; 512];
        for (index, client) in clients.iter().enumerate() {
            // Compute expected message from handshake payload
            let handshake = utils::handshake(WGPROXY_PUBKEY, index as u16);
            let expected = &handshake[4..116];

            // Receive and validate packet
            let (buf_len, _) = client.recv_from(&mut buf).expect("failed to send test packet");
            assert_eq!(&buf[..buf_len], expected);
        }
    });
}
