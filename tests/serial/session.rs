// Session-related tests

use crate::utils;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;
use std::{array, thread};
use wgproxy::config::Config;

/// Simple routing for a single `client->server->client` session
pub fn simple_routing(server: &UdpSocket, wgproxy: &SocketAddr, config: &Config) {
    // Setup client
    let client = UdpSocket::bind("127.0.0.1:0").expect("failed to create client socket");
    let handshake = utils::handshake(&config.WGPROXY_PUBKEYS[0], 0);
    let mut buf = [0; 512];

    // Send packet to the server
    client.send_to(&handshake, wgproxy).expect("failed to send test packet");
    let (buf_len, relay_nat_address) = server.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], handshake);

    // Send packet back to the client
    server.send_to(b"TESTOLOPE", relay_nat_address).expect("failed to send test reply");
    let (buf_len, _) = client.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], b"TESTOLOPE");
}

/// Interleaved routing for multiple simultaneous `client->server->client` sessions
pub fn interleaved_routing(server: &UdpSocket, wgproxy: &SocketAddr, config: &Config) {
    // Create client sockets
    let clients: [_; 63] = array::from_fn(|_| UdpSocket::bind("127.0.0.1:0").expect("failed to create client socket"));

    // Boot relay and use a scope to ensure real parallelism for reliability
    thread::scope(|scope| {
        // Send packets
        scope.spawn(|| {
            thread::sleep(Duration::from_secs(3));
            for (index, client) in clients.iter().enumerate() {
                // Create and send valid handshakes
                let handshake = utils::handshake(&config.WGPROXY_PUBKEYS[0], index as u16);
                client.send_to(&handshake, wgproxy).expect("failed to send test packet");
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
            let handshake = utils::handshake(&config.WGPROXY_PUBKEYS[0], index as u16);
            let expected = &handshake[4..116];

            // Receive and validate packet
            let (buf_len, _) = client.recv_from(&mut buf).expect("failed to send test packet");
            assert_eq!(&buf[..buf_len], expected);
        }
    });
}

/// Session timeout for a single `client->server->timeout|client->server->client` session
pub fn timeout(server: &UdpSocket, wgproxy: &SocketAddr, config: &Config) {
    // Setup client
    let client = UdpSocket::bind("127.0.0.1:0").expect("failed to create client socket");
    let handshake0 = utils::handshake(&config.WGPROXY_PUBKEYS[0], 0);
    let handshake1 = utils::handshake(&config.WGPROXY_PUBKEYS[0], 1);
    let mut buf = [0; 512];

    // Send packet to the server
    client.send_to(&handshake0, wgproxy).expect("failed to send test packet");
    let (buf_len, relay_nat_address) = server.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], handshake0);

    // Let the connection timeout, then send a packet back
    thread::sleep((config.WGPROXY_TIMEOUT * 2) + (wgproxy::POLL_TIMEOUT * 2));
    server.send_to(b"testolope:0", relay_nat_address).expect("failed to send test reply");

    // Send another packet to the server
    client.send_to(&handshake1, wgproxy).expect("failed to send test packet");
    let (buf_len, relay_nat_address) = server.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], handshake1);

    // Send second packet back to the client and ensure that only this packet arrives
    server.send_to(b"testolope:1", relay_nat_address).expect("failed to send test reply");
    let (buf_len, _) = client.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], b"testolope:1");
}
