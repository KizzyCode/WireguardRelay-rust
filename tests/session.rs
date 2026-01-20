//! Session-related test cases

mod utils;
use std::net::UdpSocket;
use std::thread;

/// Tests that a trivial handshake and subsequent session works
#[test]
pub fn handshake() {
    // Start custom proxy session for testing
    let (config, wgproxy, server) = utils::session();

    // Setup client
    let client = UdpSocket::bind("127.0.0.1:0").expect("failed to create client socket");
    let handshake = utils::handshake(&config.WGPROXY_PUBKEY);
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

/// Tests that multiple handshakes do not reset the an existing session
#[test]
pub fn handshake2() {
    // Start custom proxy session for testing
    let (config, wgproxy, server) = utils::session();

    // Setup client
    let client0 = UdpSocket::bind("127.0.0.1:0").expect("failed to create client socket");
    let client1 = UdpSocket::bind("127.0.0.1:0").expect("failed to create client socket");
    let handshake0 = utils::handshake(&config.WGPROXY_PUBKEY);
    let handshake1 = utils::handshake(&config.WGPROXY_PUBKEY);
    let mut buf = [0; 512];

    // Send packet to the server
    client0.send_to(&handshake0, wgproxy).expect("failed to send test packet");
    let (buf_len, relay_nat_address) = server.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], handshake0);

    // Send a packet back to the client
    server.send_to(b"testolope:0", relay_nat_address).expect("failed to send test reply");
    let (buf_len, _) = client0.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], b"testolope:0");

    // Do another handshake from the new address
    client1.send_to(&handshake1, wgproxy).expect("failed to send test packet");

    // Send second packet back to the client and ensure that it arrives on the old address
    server.send_to(b"testolope:1", relay_nat_address).expect("failed to send test reply");
    let (buf_len, _) = client0.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], b"testolope:1");
}

/// Tests that session timeouts are handled gracefully
#[test]
pub fn timeout() {
    // Start custom proxy session for testing
    let (config, wgproxy, server) = utils::session();

    // Setup client
    let client = UdpSocket::bind("127.0.0.1:0").expect("failed to create client socket");
    let handshake0 = utils::handshake(&config.WGPROXY_PUBKEY);
    let handshake1 = utils::handshake(&config.WGPROXY_PUBKEY);
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

/// Tests that session timeouts and address changes are handled gracefully
#[test]
pub fn timeout2() {
    // Start custom proxy session for testing
    let (config, wgproxy, server) = utils::session();

    // Setup client
    let client0 = UdpSocket::bind("127.0.0.1:0").expect("failed to create client socket");
    let client1 = UdpSocket::bind("127.0.0.1:0").expect("failed to create client socket");
    let handshake0 = utils::handshake(&config.WGPROXY_PUBKEY);
    let handshake1 = utils::handshake(&config.WGPROXY_PUBKEY);
    let mut buf = [0; 512];

    // Do handshake
    client0.send_to(&handshake0, wgproxy).expect("failed to send test packet");
    let (buf_len, relay_nat_address) = server.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], handshake0);

    // Let the connection timeout, then send a packet back
    thread::sleep(config.WGPROXY_TIMEOUT * 2);
    server.send_to(b"testolope:0", relay_nat_address).expect("failed to send test reply");

    // Do another handshake from the new address
    client1.send_to(&handshake1, wgproxy).expect("failed to send test packet");
    let (buf_len, relay_nat_address) = server.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], handshake1);

    // Send second packet back to the client and ensure that this packet arrives on the new address
    server.send_to(b"testolope:1", relay_nat_address).expect("failed to send test reply");
    let (buf_len, _) = client1.recv_from(&mut buf).expect("failed to receive test packet");
    assert_eq!(&buf[..buf_len], b"testolope:1");
}

/// Tests that a trivial handshake and subsequent session works with a bunch of messages
#[test]
pub fn batch() {
    // Start custom proxy session for testing
    let (config, wgproxy, server) = utils::session();

    // Setup client
    let client = UdpSocket::bind("127.0.0.1:0").expect("failed to create client socket");
    let handshake = utils::handshake(&config.WGPROXY_PUBKEY);
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
