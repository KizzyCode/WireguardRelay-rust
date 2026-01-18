// Session-related tests

use crate::utils;
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use wgproxy::config::Config;

/// Tests that a trivial handshake and subsequent session works
pub fn handshake(server: &UdpSocket, wgproxy: &SocketAddr, config: &Config) {
    // Setup client
    let client = UdpSocket::bind("127.0.0.1:0").expect("failed to create client socket");
    let handshake = utils::handshake(&config.WGPROXY_PUBKEY, 0);
    let mut buf = [0; 512];

    // Do handshake
    client.send_to(&handshake, wgproxy).expect("failed to send test packet");
    let (buf_len, relay_nat_address) = server.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], handshake);

    // Send packet back to the client
    server.send_to(b"TESTOLOPE", relay_nat_address).expect("failed to send test reply");
    let (buf_len, _) = client.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], b"TESTOLOPE");
}

/// Tests that multiple handshakes reset the session accordingly
pub fn handshake2(server: &UdpSocket, wgproxy: &SocketAddr, config: &Config) {
    // Setup client
    let client0 = UdpSocket::bind("127.0.0.1:0").expect("failed to create client socket");
    let client1 = UdpSocket::bind("127.0.0.1:0").expect("failed to create client socket");
    let handshake0 = utils::handshake(&config.WGPROXY_PUBKEY, 0);
    let handshake1 = utils::handshake(&config.WGPROXY_PUBKEY, 1);
    let mut buf = [0; 512];

    // Send packet to the server
    client0.send_to(&handshake0, wgproxy).expect("failed to send test packet");
    let (buf_len, relay_nat_address) = server.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], handshake0);

    // Send a packet back to the client
    server.send_to(b"testolope:0", relay_nat_address).expect("failed to send test reply");
    let (buf_len, _) = client0.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], b"testolope:0");

    // Do another handshake
    client1.send_to(&handshake1, wgproxy).expect("failed to send test packet");
    let (buf_len, relay_nat_address) = server.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], handshake1);

    // Send second packet back to the client and ensure that it arrives on the new address
    server.send_to(b"testolope:1", relay_nat_address).expect("failed to send test reply");
    let (buf_len, _) = client1.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], b"testolope:1");
}

/// Tests that session timeouts are handled gracefully
pub fn timeout(server: &UdpSocket, wgproxy: &SocketAddr, config: &Config) {
    // Setup client
    let client = UdpSocket::bind("127.0.0.1:0").expect("failed to create client socket");
    let handshake0 = utils::handshake(&config.WGPROXY_PUBKEY, 0);
    let handshake1 = utils::handshake(&config.WGPROXY_PUBKEY, 1);
    let mut buf = [0; 512];

    // Do handshake
    client.send_to(&handshake0, wgproxy).expect("failed to send test packet");
    let (buf_len, relay_nat_address) = server.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], handshake0);

    // Let the connection timeout, then send a packet back
    thread::sleep(config.WGPROXY_TIMEOUT * 2);
    server.send_to(b"testolope:0", relay_nat_address).expect("failed to send test reply");

    // Do another handshake
    client.send_to(&handshake1, wgproxy).expect("failed to send test packet");
    let (buf_len, relay_nat_address) = server.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], handshake1);

    // Send second packet back to the client and ensure that only this packet arrives
    server.send_to(b"testolope:1", relay_nat_address).expect("failed to send test reply");
    let (buf_len, _) = client.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], b"testolope:1");
}

/// Tests that a trivial handshake and subsequent session works with a bunch of messages
pub fn batch(server: &UdpSocket, wgproxy: &SocketAddr, config: &Config) {
    // Setup client
    let client = UdpSocket::bind("127.0.0.1:0").expect("failed to create client socket");
    let handshake = utils::handshake(&config.WGPROXY_PUBKEY, 0);
    let mut buf = [0; 512];

    // Do handshake
    client.send_to(&handshake, wgproxy).expect("failed to send test packet");
    let (buf_len, relay_nat_address) = server.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], handshake);

    // Send a lot of messages
    for index in 0usize..65536 {
        // Send packet to the server
        let message = index.to_ne_bytes();
        client.send_to(&message, relay_nat_address).expect("failed to send test reply");
        let (buf_len, _) = server.recv_from(&mut buf).expect("failed to receive test packet");
        assert_eq!(&buf[..buf_len], &message);

        // Send packet back to the client
        let message = (!index).to_ne_bytes();
        server.send_to(&message, relay_nat_address).expect("failed to send test reply");
        let (buf_len, _) = client.recv_from(&mut buf).expect("failed to receive test packet");
        assert_eq!(&buf[..buf_len], &message);
    }
}
