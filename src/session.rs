//! The relay session

use crate::config::Config;
use crate::error;
use crate::error::Error;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Instant;
use std::{cmp, fmt};

/// Extends [`SocketAddr`]
trait SocketAddrExt {
    /// Canonicalizes a socket address relative to the given target address family
    fn canonical(&self, target_family: &Self) -> Self;
}
impl SocketAddrExt for SocketAddr {
    fn canonical(&self, target_family: &Self) -> Self {
        // v6-to-v4 chain
        if target_family.is_ipv4()
            && let IpAddr::V6(address_v6) = self.ip()
            && let Some(canonical_v4) = address_v6.to_ipv4()
        {
            // We could map the address to v4
            return SocketAddr::new(IpAddr::V4(canonical_v4), self.port());
        }

        // v4-to-v6 chain
        if target_family.is_ipv6()
            && let IpAddr::V4(address_v4) = self.ip()
        {
            // We can map the address to v6
            let canonical_v6 = address_v4.to_ipv6_mapped();
            return SocketAddr::new(IpAddr::V6(canonical_v6), self.port());
        }

        // No mapping possible or necessary
        *self
    }
}

/// A relay session
#[derive(Debug)]
pub struct Session<'a> {
    /// The forwarding socket
    socket: &'a UdpSocket,
    /// The client address for this session
    client_address: SocketAddr,
    /// The server address for this session
    server_address: SocketAddr,
    /// The last uplink atime
    last_uplink: Instant,
    /// The last downlink atime
    last_downlink: Instant,
}
impl<'a> Session<'a> {
    /// Creates a new relay session with the given incoming handshake packet
    pub fn new(client_address: &SocketAddr, config: &Config, socket: &'a UdpSocket) -> Result<Self, Error> {
        // Resolve server address
        let mut server_addresses = (config.WGPROXY_SERVER.to_socket_addrs())
            .map_err(|e| error!(with: e, "Failed to resolve server address"))?;
        let server_address = server_addresses.next().ok_or(error!("Failed to resolve server address"))?;

        // Canonicalize socket addresses so we always have the same family as our listening socket
        let server_address = server_address.canonical(&config.WGPROXY_LISTEN);
        let client_address = client_address.canonical(&config.WGPROXY_LISTEN);

        // Init self
        let last_uplink = Instant::now();
        let last_downlink = Instant::now();
        Ok(Self { socket, client_address, server_address, last_uplink, last_downlink })
    }

    /// Forward an incoming packet if appropriate
    pub fn forward(&mut self, packet: &[u8], source: &SocketAddr) -> Result<(), Error> {
        // Route packet accordingly
        if self.client_address.eq(source) {
            // Forward client packet to server
            self.socket.send_to(packet, &self.server_address)?;
            self.last_uplink = Instant::now();
            Ok(())
        } else if self.server_address.eq(source) {
            // Forward server packet to client
            self.socket.send_to(packet, &self.client_address)?;
            self.last_downlink = Instant::now();
            Ok(())
        } else {
            // Cannot associate packet source
            Err(error!("Unknown packet from {source}"))
        }
    }

    /// The latest atime of this session
    pub fn atime(&self) -> Instant {
        // Keep-alives should be symmetrical, so we use the **older** atime as reference – if one atime drifts beyond
        //  the timeout threshold, something is probably wrong, even if the other atime is updated.
        cmp::min(self.last_uplink, self.last_downlink)
    }
}
impl Display for Session<'_> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Encode some fields for better readability
        let socket = self.socket.local_addr().ok();
        let last_uplink = self.last_uplink.elapsed();
        let last_downlink = self.last_downlink.elapsed();

        // Format struct
        f.debug_struct("Session")
            .field("socket", &socket)
            .field("client_address", &self.client_address)
            .field("server_address", &self.server_address)
            .field("last_uplink", &last_uplink)
            .field("last_downlink", &last_downlink)
            .finish()
    }
}
