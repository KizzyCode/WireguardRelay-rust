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
mod handshake;
mod session;

use crate::config::Config;
use crate::error::Error;
use crate::handshake::Handshake;
use crate::session::Session;
use std::cell::Cell;
use std::convert::Infallible;
use std::net::UdpSocket;

thread_local! {
    /// Thread-global log level to allow context-free logging
    pub(crate) static LOGLEVEL: Cell<u8> = Cell::new(1);
}

/// The packet-forwarding event loop
pub fn eventloop(config: Config) -> Result<Infallible, Error> {
    // Set log-level from config
    LOGLEVEL.set(config.WGPROXY_LOGLEVEL);
    log!(info: &config);

    // Setup relay state
    let socket = UdpSocket::bind(config.WGPROXY_LISTEN)?;
    let validator = Handshake::new(config.WGPROXY_PUBKEY);
    let mut session: Option<Session> = None;

    // Start network loop
    let mut buf = [0; 4096];
    'network_loop: loop {
        // Receive next inbound packet
        let (buf_len, source_addr) =
            socket.recv_from(&mut buf).map_err(|e| error!(with: e, "Failed to receive inbound packet"))?;
        let packet = &buf[..buf_len];

        // Check for session timeouts
        if let Some(session_) = session.as_ref()
            && session_.atime().elapsed() > config.WGPROXY_TIMEOUT
        {
            // Drop session
            log!(info: error!("Dropping expired session {session_}"));
            session = None;
        }

        // Always start a new session if a packet is a handshake packet
        if let Ok(_) = log!(debug: validator.is_valid_handshake(packet)) {
            // If we cannot create a new session, this is probably fatal
            let session_ = Session::new(&source_addr, &config, &socket)?;
            session = Some(session_);
        }

        // Unpack current session or log info
        let Some(session) = session.as_mut() else {
            // This is not an error as rogue packets may arrive anytime
            log!(debug: error!("Cannot forward packet without valid session"));
            continue 'network_loop;
        };

        // Forward the packet
        let Ok(()) = log!(warn: session.forward(packet, &source_addr)) else {
            // This is not necessarily fatal, but worth a warning
            continue 'network_loop;
        };
    }
}
