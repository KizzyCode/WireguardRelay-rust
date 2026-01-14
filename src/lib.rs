#![doc = include_str!("../README.md")]
// Clippy lints
#![warn(clippy::large_stack_arrays)]
#![warn(clippy::arithmetic_side_effects)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::indexing_slicing)]
#![warn(clippy::panic)]
#![warn(clippy::todo)]
#![warn(clippy::unimplemented)]
#![warn(clippy::unreachable)]
#![warn(clippy::missing_panics_doc)]
#![warn(clippy::allow_attributes_without_reason)]
#![warn(clippy::cognitive_complexity)]

pub mod config;
pub mod error;
mod session;
mod socket;
mod validator;

use crate::config::Config;
use crate::error::Error;
use crate::session::{Route, SessionPool};
use crate::socket::{SocketAddrExt, SocketPool};
use crate::validator::HandshakeValidator;
use mio::Interest;
use std::cell::Cell;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// The poll timeout to ensure the eventloop loops even without I/O
pub const POLL_TIMEOUT: Duration = Duration::from_secs(7);

thread_local! {
    /// Thread-global log level to allow context-free logging
    pub(crate) static LOGLEVEL: Cell<u8> = Cell::new(1);
}

/// The packet-forwarding event loop
///
/// # Panics
/// This function panics if it is called
pub fn eventloop(config: Config) -> Result<Infallible, Error> {
    // Set log-level from config
    LOGLEVEL.set(config.WGPROXY_LOGLEVEL);
    log!(info: &config);

    // Create and populate socket pool
    let mut socketpool = SocketPool::new()?;
    for port in config.WGPROXY_PORTS {
        // Create a new static socket for the given port
        let address = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
        socketpool.init(address, Interest::READABLE)?;
    }

    // Create session pool and handshake validator
    let mut sessionpool = SessionPool::new();
    let handshake_validator = HandshakeValidator::new(&config.WGPROXY_PUBKEYS);

    loop {
        // Wait for socket events and garbage-collect expired sessions
        socketpool.wait_for_io(POLL_TIMEOUT)?;
        sessionpool.retain(|session| {
            // See if the session has expired by comparing the atime
            let expired = session.atime().elapsed() > config.WGPROXY_TIMEOUT;
            expired.then(|| log!(info: error!("Dropping expired session: {session}")));
            !expired
        });

        // Process all incoming events
        'process_events: for event in socketpool.events() {
            // Get the associated socket for the current event
            // Note: This should never fail as the sockets are static and the events should always match
            let socket = socketpool.by_token(&event.token()).expect("failed to get socket for event token");

            // Fully drain the socket so it can be polled again
            // Note: This is necessary as otherwise the socket will be considered waiting even if it has pending I/O, as
            //  I/O-events that a part of this poll will not be considered for the next invocation anymore; even if they
            //  have not been consumed yet.
            'drain_socket: loop {
                // Receive next pending packet, or continue with the next socket
                // TODO: Make MTU configurable?
                let mut packet_buf = [0; 4096];
                let Ok((packet_len, source_address)) = socket.recv_from(&mut packet_buf) else {
                    // An error here is harmless, but this socket is probably exhausted for now
                    continue 'process_events;
                };

                // Define the route if the session exists already
                let inbound_route = Route::new(socket.address(), source_address.to_canonicalized_ipv6());
                let session = if let Some(existing_session) = sessionpool.by_route(&inbound_route) {
                    // Reuse the existing session
                    existing_session
                } else {
                    // Sanity check by verifying MAC1 with the target's public key for new sessions
                    let Ok(_) = log!(info: handshake_validator.validate(&packet_buf[..packet_len])) else {
                        // The packet is not a valid handshake packet
                        continue 'drain_socket;
                    };

                    // Find a socket where the local address is not routed yet
                    let all_addresses = socketpool.addresses();
                    let used_addresses = sessionpool.addresses();
                    let Some(new_address) = all_addresses.difference(&used_addresses).next() else {
                        // We are at full capacity, which is not fatal but blocks new sessions
                        log!(warn: error!("No available outbound ports left; cannot start another session"));
                        continue 'drain_socket;
                    };

                    // Create a new session
                    let outbound_route = Route::new(*new_address, config.WGPROXY_SERVER.to_canonicalized_ipv6());
                    sessionpool.init(inbound_route, outbound_route)
                };

                // Forward the packet
                let Ok(_) = log!(warn: session.forward(&packet_buf[..packet_len], &inbound_route, &socketpool)) else {
                    // This is not necessarily fatal, but might also be caused by spurious network problems
                    continue 'drain_socket;
                };
            }
        }
    }
}
